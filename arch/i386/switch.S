/* void switch_task(uint32_t *old_esp_out, uint32_t new_esp)
 *
 * Saves the current task's callee-saved registers + flags on its own stack,
 * stores the resulting esp through old_esp_out, then loads new_esp and restores
 * the next task's state. Returning resumes wherever that task last switched. */
.section .text
.global switch_task
.type switch_task, @function
switch_task:
    movl 4(%esp), %eax          /* old_esp_out */
    movl 8(%esp), %edx          /* new_esp */

    pushfl
    pushl %ebp
    pushl %ebx
    pushl %esi
    pushl %edi

    movl %esp, (%eax)           /* save current esp */
    movl %edx, %esp             /* load next task's esp */

    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    popfl
    ret
