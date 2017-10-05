#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/unistd.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>
#include "interceptor.h"


MODULE_DESCRIPTION("My kernel module");
MODULE_AUTHOR("Me");
MODULE_LICENSE("GPL");

//----- System Call Table Stuff ------------------------------------
/* Symbol that allows access to the kernel system call table */
extern void* sys_call_table[];

/* The sys_call_table is read-only => must make it RW before replacing a syscall */
void set_addr_rw(unsigned long addr) {

	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

/* Restores the sys_call_table as read-only */
void set_addr_ro(unsigned long addr) {

	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	pte->pte = pte->pte &~_PAGE_RW;

}
//-------------------------------------------------------------


//----- Data structures and bookkeeping -----------------------
/**
 * This block contains the data structures needed for keeping track of
 * intercepted system calls (including their original calls), pid monitoring
 * synchronization on shared data, etc.
 * It's highly unlikely that you will need any globals other than these.
 */

/* List structure - each intercepted syscall may have a list of monitored pids */
struct pid_list {
	pid_t pid;
	struct list_head list;
};


/* Store info about intercepted/replaced system calls */
typedef struct {

	/* Original system call */
	asmlinkage long (*f)(struct pt_regs);

	/* Status: 1=intercepted, 0=not intercepted */
	int intercepted;

	/* Are any PIDs being monitored for this syscall? */
	int monitored;
	/* List of monitored PIDs */
	int listcount;
	struct list_head my_list;
}mytable;

/* An entry for each system call in this "metadata" table */
mytable table[NR_syscalls];

/* Access to the system call table and your metadata table must be synchronized */
spinlock_t my_table_lock = SPIN_LOCK_UNLOCKED;
spinlock_t sys_call_table_lock = SPIN_LOCK_UNLOCKED;
//-------------------------------------------------------------


//----------LIST OPERATIONS------------------------------------
/**
 * These operations are meant for manipulating the list of pids 
 * Nothing to do here, but please make sure to read over these functions 
 * to understand their purpose, as you will need to use them!
 */

/**
 * Add a pid to a syscall's list of monitored pids. 
 * Returns -ENOMEM if the operation is unsuccessful.
 */
static int add_pid_sysc(pid_t pid, int sysc)
{
	struct pid_list *ple=(struct pid_list*)kmalloc(sizeof(struct pid_list), GFP_KERNEL);

	if (!ple)
		return -ENOMEM;

	INIT_LIST_HEAD(&ple->list);
	ple->pid=pid;
	list_add(&ple->list, &(table[sysc].my_list));
	table[sysc].listcount++;

	return 0;
}

/**
 * Remove a pid from a system call's list of monitored pids.
 * Returns -EINVAL if no such pid was found in the list.
 */
static int del_pid_sysc(pid_t pid, int sysc)
{
	struct list_head *i;
	struct pid_list *ple;

	list_for_each(i, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		if(ple->pid == pid) {

			list_del(i);
			kfree(ple);

			table[sysc].listcount--;
			/* If there are no more pids in sysc's list of pids, then
			 * stop the monitoring only if it's not for all pids (monitored=2) */
			if(table[sysc].listcount == 0 && table[sysc].monitored == 1) {
				table[sysc].monitored = 0;
			}

			return 0;
		}
	}

	return -EINVAL;
}

/**
 * Remove a pid from all the lists of monitored pids (for all intercepted syscalls).
 * Returns -1 if this process is not being monitored in any list.
 */
static int del_pid(pid_t pid)
{
	struct list_head *i, *n;
	struct pid_list *ple;
	int ispid = 0, s = 0;

	for(s = 1; s < NR_syscalls; s++) {

		list_for_each_safe(i, n, &(table[s].my_list)) {

			ple=list_entry(i, struct pid_list, list);
			if(ple->pid == pid) {

				list_del(i);
				ispid = 1;
				kfree(ple);

				table[s].listcount--;
				/* If there are no more pids in sysc's list of pids, then
				 * stop the monitoring only if it's not for all pids (monitored=2) */
				if(table[s].listcount == 0 && table[s].monitored == 1) {
					table[s].monitored = 0;
				}
			}
		}
	}

	if (ispid) return 0;
	return -1;
}

/**
 * Clear the list of monitored pids for a specific syscall.
 */
static void destroy_list(int sysc) 
{
	struct list_head *i, *n;
	struct pid_list *ple;

	list_for_each_safe(i, n, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		list_del(i);
		kfree(ple);
	}

	table[sysc].listcount = 0;
	table[sysc].monitored = 0;
}

/**
 * Check if two pids have the same owner - useful for checking if a pid 
 * requested to be monitored is owned by the requesting process.
 * Remember that when requesting to start monitoring for a pid, only the 
 * owner of that pid is allowed to request that.
 */
static int check_pids_same_owner(pid_t pid1, pid_t pid2) 
{
	struct task_struct *p1 = pid_task(find_vpid(pid1), PIDTYPE_PID);
	struct task_struct *p2 = pid_task(find_vpid(pid2), PIDTYPE_PID);
	if(p1->real_cred->uid != p2->real_cred->uid)
		return -EPERM;
	return 0;
}

/**
 * Check if a pid is already being monitored for a specific syscall.
 * Returns 1 if it already is, or 0 if pid is not in sysc's list.
 */
static int check_pid_monitored(int sysc, pid_t pid) 
{
	struct list_head *i;
	struct pid_list *ple;

	list_for_each(i, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		if(ple->pid == pid) 
			return 1;
		
	}
	return 0;	
}
//----------------------------------------------------------------

//----- Intercepting exit_group ----------------------------------
/**
 * Since a process can exit without its owner specifically requesting
 * to stop monitoring it, we must intercept the exit_group system call
 * so that we can remove the exiting process's pid from *all* syscall lists.
 */  

/** 
 * Stores original exit_group function - after all, we must restore it 
 * when our kernel module exits.
 */
void (*orig_exit_group)(int);

/**
 * A function that wraps the exit system call, removing any pids that
 * exit from the system call monitoring list.
 */
void my_exit_group(int status)
{
	pid_t pid;
	pid = current -> pid;
	spin_lock(&my_table_lock);
	del_pid(pid);
    orig_exit_group(status);
    spin_unlock(&my_table_lock);
}
//----------------------------------------------------------------

/**
 * A function used to replace system calls in the sys_call_table.
 * 
 * This function is merely a wrapper for the system call and only 
 * outputs a text via the log_message macro when the current system
 * call and pid are being intercepted and monitored.
 */
asmlinkage long interceptor(struct pt_regs reg) 
{
    long ret; // Value returned by original function
    pid_t pid; // Current pid
    int syscall; // system call being executed
    syscall = reg.orig_ax;
    pid = current->pid;
    
    spin_lock(&my_table_lock);
    if (table[syscall].intercepted == 2 || check_pid_monitored(syscall, pid)) { // Only log if the pid is monitored for the syscall
        log_message(pid, reg.ax, reg.bx, reg.cx, reg.dx, reg.si, reg.di, reg.bp);
    }

    // Call the original function to resume proper functionality
    ret = table[syscall].f(reg);
    spin_unlock(&my_table_lock);
	return ret; 
}

//----- Utility methods for pids ---------------------------------
/**
 * Returns 1 if a pid is valid, 0 otherwise
 */
asmlinkage int is_pid_valid(int pid) 
{
    // We consider '0' to indicate all pids
    if (pid == 0) {
        return 1;
    }
    
    // Check if the pid provided is valid (ie. non-negative and exists)
    if (pid < 0 || pid_task(find_vpid(pid), PIDTYPE_PID) == NULL) {
        return 0;
    }
    
    return 1;
}

/**
 * Returns 1 if the current user can change monitoring state of a pid, 0 otherwise.
 * This method assumes the pid is either 0 (indicating all pids) or is in fact valid.
 */
asmlinkage int can_control_monitor(int pid) 
{
    struct task_struct *pid_task_struct;
    if (current_uid() == 0) {
        return 1;
    } else if (pid == 0){
        return 0; // Not root and 'all' pids
    }
    pid_task_struct = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (check_pids_same_owner(pid_task_struct->pid, get_current()->pid) == -EPERM) {
        return 0;
    }
    return 1;
}
//----------------------------------------------------------------

//----- MY_CUSTOM_SYSCALL command functions ----------------------
/**
 * Intercepts a system call
 *
 * Returns:
 * * -EPERM if the current user is not root
 * * -EBUSY if the system call is already intercepted
 * * 0 when a system call is successfully intercepted
 */
asmlinkage long syscall_intercept(int syscall) 
{
	long (*orig_syscall)(void);

	// Require the current user issuing the request to be the root user
	if (current_uid() != 0) {
		return -EPERM;
	}

	// Acquire a lock since we are going to be messing with entries
	// in the table array.
	spin_lock(&my_table_lock);

	// If the system call is already being intercepted (ie. is 1 or 2)
	// we return an -EBUSY signal.
    if (table[syscall].intercepted != 0) {
        spin_unlock(&my_table_lock); // Unlock!
        return -EBUSY;
    }

    // All good to go - we now set up the struct in the syscall index
    // to indicate that it is being intercepted. 
    table[syscall].intercepted = 1;
    
    // Fetch the original system call and save it in the mytable struct
    // in the array. We first acquire a lock on the sys_call_table in order
    // to safely read the current value.
    spin_lock(&sys_call_table_lock);
    orig_syscall = (long (*) (void)) sys_call_table[syscall]; 
    table[syscall].f=(asmlinkage long (*) (struct pt_regs))orig_syscall;

    // Replace the system call with our interceptor function
    set_addr_rw((unsigned long) sys_call_table); 
    sys_call_table[syscall] = interceptor;
    set_addr_ro((unsigned long) sys_call_table);

    // Release our locks to allow any other methods to interact with the table 
    // and sys_call_table arrays.
    spin_unlock(&sys_call_table_lock);
    spin_unlock(&my_table_lock);
    return 0;
}

/* Helper method to properly release a system call and restore the previous function */
asmlinkage void _syscall_release(int syscall)
{
	// Acquire a lock on the system call table to restore the original system call
    // We must set RW before writing, and then RO to revert the operation.
    spin_lock(&sys_call_table_lock);
    set_addr_rw((unsigned long) sys_call_table); 
    sys_call_table[syscall] = table[syscall].f;
    set_addr_ro((unsigned long) sys_call_table);
    spin_unlock(&sys_call_table_lock);

    // Reset the system call information to "factory settings"
    table[syscall].intercepted = 0;
    destroy_list(syscall);
    table[syscall].f = NULL;
}

/**
 * Releases a system call from being intercepted
 * 
 * Returns:
 * * -EPERM if the user is not root
 * * -EINVAL if the call is not intercepted
 * * 0 when a systemcall is successfully released
 */
asmlinkage long syscall_release(int syscall) 
{
	// Require the current user issuing the request to be the root user
	if (current_uid() != 0) 
        return -EPERM;

    // Acquire a lock since we are going to be messing with entries
	// in the table array.
    spin_lock(&my_table_lock);

    // If the requested syscall isn't being monitored we return -EINVAL.
    if (table[syscall].intercepted == 0) {
        spin_unlock(&my_table_lock); 
        return -EINVAL;
    }

    _syscall_release(syscall);
    spin_unlock(&my_table_lock);
    return 0;
}

/**
 * Begins monitoring a certain PID for a system call. A pid 
 * of '0' indicates that the module should monitor all PIDs 
 * for the system call. However, the user must be root to 
 * monitor all calls.
 *
 * Returns:
 * * -EINVAL if an invalid pid is provided
 * * -EPERM if the user is not root and does not own the process
 * * -EBUSY if the pid is already monitored for the system call
 * * -EINVAL if the system call is not being intercepted
 * * -ENOMEM if the kernel does not have enough memory to continue
 * * 0 when a pid begins being monitored
 */
asmlinkage long start_monitoring(int syscall, int pid) 
{
	pid_t valid_pid;

	// Check if the pid is a valid pid that we can begin monitoring
    if (!is_pid_valid(pid)) {
        return -EINVAL;
    } 

   	// Check if the current user can monitor the passed in pid
    if (!can_control_monitor(pid)) {
        return -EPERM;
    }

    // Acquire a lock to handle information in the table array
    spin_lock(&my_table_lock);

    // Check if all processes are already monitored: ret -EBUSY if true
    if (table[syscall].intercepted == 2) {
    	spin_unlock(&my_table_lock);
        return -EBUSY; 
    }

    // If the system call is not being monitored: return -EINVAL
    if (table[syscall].intercepted == 0) {
        spin_unlock(&my_table_lock);
        return -EINVAL;        
    }

    // Check if we are attempting to monitor all processes, otherwise handle
    // for a single pid
    if (pid == 0) {
        // Set the state of the system call to 2 (all intercepted), we destroy the 
        // list of the system call to remove all of the currently stored pids as the
        // only way to reverse this is by stopping to monitor all pids.
        table[syscall].intercepted = 2;
        destroy_list(syscall);
    } else {
        valid_pid = pid_task(find_vpid(pid), PIDTYPE_PID)->pid;
        
        // If the passed in pid is already being monitored for the system call we
        // return -EBUSY
        if (check_pid_monitored(syscall, valid_pid)) { // Check if the PID is already monitored
            spin_unlock(&my_table_lock);
            return -EBUSY;
        }
        
        // Add the pid to the list held for the system call. If add_pid_sysc errors
        // out due to no memory, this function returns the error value.
        if (add_pid_sysc(valid_pid, syscall) == -ENOMEM) {
            spin_unlock(&my_table_lock);
            return -ENOMEM;
        }
    }

    spin_unlock(&my_table_lock); 
	return 0;
}

/**
 * Stops monitoring a pid for a specific system call.
 * 
 * Returns:
 * * -EINVAL if the pid is invalid
 * * -EPERM if the user is not root and cannot monitor the pid
 * * -EINVAL if the system call is not intercepted
 * * -EINVAL if the pid is not being monitored for the system call
 * * 0 when the pid is successfully removed from the monitor list
 */
asmlinkage long stop_monitoring(int syscall, int pid) 
{
    pid_t valid_pid;

    // Check if the pid is a valid pid that we can begin monitoring
    if (!is_pid_valid(pid)) {
        return -EINVAL;
    } 
    
    // Check if the current user can monitor the passed in pid
    if (!can_control_monitor(pid)) {
        return -EPERM;
    }

    spin_lock(&my_table_lock);
        
    // TODO: Bonus can be implemented here (if all are monitored- blacklist)

    // Check if the system call is even being intercepted: return -EINVAL if not
    if (table[syscall].intercepted == 0) {
        spin_unlock(&my_table_lock);
        return -EINVAL;
    }
    
    // If the pid is 0 then we must clear the list of monitored pids
    if (pid == 0) {
        table[syscall].intercepted = 1; // Set it to only intercept single pids
        destroy_list(syscall);
    } else { // Targetting a specific pid to stop monitoring
        valid_pid = pid_task(find_vpid(pid), PIDTYPE_PID)->pid; // Parse the valid pid
        // If the pid is not being monitored we must return -EINVAL
        if (!check_pid_monitored(syscall, valid_pid)) { 
            spin_unlock(&my_table_lock);
            return -EINVAL;
        }

        // Delete the pid from the system call. This method should never return
        // -EINVAL at this point however for safety we pass the value.
        if (del_pid_sysc(valid_pid, syscall) == -EINVAL) {
        	spin_unlock(&my_table_lock);
            return -EINVAL;        
        }
    }
 
    spin_unlock(&my_table_lock);
    return 0;
}

/**
 * My system call - this function is called whenever a user issues a MY_CUSTOM_SYSCALL system call.
 * When that happens, the parameters for this system call indicate one of 4 actions/commands:
 *      - REQUEST_SYSCALL_INTERCEPT to intercept the 'syscall' argument
 *      - REQUEST_SYSCALL_RELEASE to de-intercept the 'syscall' argument
 *      - REQUEST_START_MONITORING to start monitoring for 'pid' whenever it issues 'syscall' 
 *      - REQUEST_STOP_MONITORING to stop monitoring for 'pid'
 *      For the last two, if pid=0, that translates to "all pids".
 * 
 * This system call will return 1 of 5 values:
 * * -EPERM when the user does not have permission to modify intercept or monitor
 * 	 state of a system call or pid
 * * -EINVAL if an invalid system call, pid, value, or state is found
 * * -ENOMEM if the kernel runs out of memory when tring to handle a call
 * * -EBUSY if a system call or pid are being intercepted or monitored (resp.)
 * * 0 when a successful command is performed.
 *
 * More information can be read about on specific cases by referencing the documentation
 * for the syscall_intercept, syscall_release, start_monitoring, and stop_monitoring
 * functions.
 */
asmlinkage long my_syscall(int cmd, int syscall, int pid) 
{
	printk(KERN_ERR "my_syscall\n");
    // Don't allow invalid syscall to be tracked, also cannot be our custom syscall
    if (syscall < 0 || syscall > NR_syscalls-1 || syscall == MY_CUSTOM_SYSCALL) {
    	printk(KERN_ERR "inval\n");
        return -EINVAL;
    }

    // Find out which command has been requested and process with the proper arguments
    if (cmd == REQUEST_SYSCALL_INTERCEPT) { 
    	printk(KERN_ERR "intercept\n");
    	return syscall_intercept(syscall);
    } else if (cmd == REQUEST_SYSCALL_RELEASE) {
    	printk(KERN_ERR "release\n");
    	return syscall_release(syscall);
    } else if (cmd == REQUEST_START_MONITORING) {
    	printk(KERN_ERR "start\n");
        return start_monitoring(syscall, pid);
    } else if (cmd == REQUEST_STOP_MONITORING) {
    	printk(KERN_ERR "stop\n");
         return stop_monitoring(syscall, pid);
    } else {
        // An invalid command was provided so we return -EINVAL
        return -EINVAL;
    }
}
//----------------------------------------------------------------


//----- Module initialization and de-initialization --------------
/**
 * The original system call that was in place at index MY_CUSTOM_SYSCALL
 * when the module initialized. This value is used to restore the original
 * function when the module exits.
 */
long (*orig_custom_syscall)(void);

/** 
 * Initializes the module, hijacking MY_CUSTOM_SYSCALL in order to allow
 * intercepting of specific system calls and pids.
 */
static int init_function(void) 
{
	int i;
    asmlinkage long (* my_syscall_ptr) (int, int, int);
    void (* my_exit_group_ptr) (int);
    my_syscall_ptr = my_syscall;
    my_exit_group_ptr = my_exit_group;

	printk(KERN_ERR "init_function\n");

    spin_lock(&my_table_lock);
    // Initialize all the list structures for our system calls
    for (i = 0 ; i < NR_syscalls ; i++) {
    	INIT_LIST_HEAD(&table[i].my_list);
    }
    spin_unlock(&my_table_lock);

    spin_lock(&sys_call_table_lock);
    orig_custom_syscall = (long (*) (void)) sys_call_table[MY_CUSTOM_SYSCALL];    
    orig_exit_group = (void (*) (int)) sys_call_table[__NR_exit_group];
    // Get a pointer to my_sys_call and write it to MY_CUSTOM_SYSCALL
    set_addr_rw((unsigned long) sys_call_table); // Enable writing to sys call table
    sys_call_table[MY_CUSTOM_SYSCALL] = my_syscall_ptr;
    sys_call_table[__NR_exit_group] = my_exit_group_ptr;
    set_addr_ro((unsigned long) sys_call_table); // Write read only again
    spin_unlock(&sys_call_table_lock);

    printk(KERN_ERR "done!\n");
	return 0;
}

/**
 * Exits the module, cleaning up and restoring the original functionality
 * of kernel system calls
 */
static void exit_function(void)
{
	int i;

	// Restore any system calls that we have intercepted to their original 
	// function value
	spin_lock(&my_table_lock);
    for (i = 0 ; i < NR_syscalls ; i++) {
    	if (table[i].intercepted != 0) {
    		_syscall_release(i);
    	}
    }
    spin_unlock(&my_table_lock);

    // Restore the original system call at index MY_CUSTOM_SYSCALL as well
    // as the exit group system call.
    spin_lock(&sys_call_table_lock);
    set_addr_rw((unsigned long) sys_call_table); // Enable writing
    sys_call_table[MY_CUSTOM_SYSCALL] = orig_custom_syscall;
    sys_call_table[__NR_exit_group] = orig_exit_group;
    set_addr_ro((unsigned long) sys_call_table);
    spin_unlock(&sys_call_table_lock);
    // General cleanup of variables
    orig_custom_syscall = NULL;
    orig_exit_group = NULL;
}
//----------------------------------------------------------------

module_init(init_function);
module_exit(exit_function);

