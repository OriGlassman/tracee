# do_arch_prctl_64

## Intro
do_arch_prctl_64 - do arch_prctl main logic

## Description
An event indicating the execution of arch_prctl

## Arguments
* `option`:`const char*`[K] - the operation to be performed.
* `address`:`const char*`[K] - either value to be set or an address.

## Hooks
### do_arch_prctl_64

#### Type

kprobe

#### Purpose

To capture calls to arch_prctl syscall

## Example Use Case

```console
./tracee -e do_arch_prctl_64
```

## Issues

## Related Events
