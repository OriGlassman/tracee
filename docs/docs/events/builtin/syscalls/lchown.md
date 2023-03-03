
# lchown

## Intro
lchown - changing the ownership of a file or symlink

## Description
The lchown() system call changes the owner and the group of a given file or symlink. This syscall differs from the chown syscall in that it does not follow symlinks. This can be useful in certain scenarios, for example, when setting the owner of a mount point, or when changing the ownership of files in a readable directory that has been exposed on the target system. The lchown() system call may be vulnerable to a race condition known as TOCTOU (time of check, time of use), as this syscall does not provide atomic guarantee on the ownership change.

## Arguments
* `pathname`: `const char*`[KU] - Pathname of the file or symlink to be changed.
* `owner`: `uid_t`[K] - User ID of the new owner.
* `group`: `gid_t`[K] - Group ID of the new group.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### sys_lchown
#### Type
Kprobe + Kretprobe
#### Purpose
What the probes are designed to achieve. Instrumentation of the file or symlink ownership change operation.

## Example Use Case
A use case for this event could be creating an audit trail of ownership changes on sensitive files in the system, such as config files and binaries.

## Issues
If there is an issue with this event, this is the place to write it.

## Related Events
 * `chown` - For changing ownership on a pathname, including symlinks

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracee recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.