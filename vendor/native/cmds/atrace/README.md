# Atrace categories

The atrace command (and the perfetto configuration) allow listing **categories**
to select subsets of events to be traced.

Each category can include some userspace events and some ftrace events.

## Vendor categories

It's possible to extend exiting categories (or to define new categories) from
the /vendor partition in order to add hardware specific ftrace events.

Since android 14, if the file `/vendor/etc/atrace/atrace_categories.txt`, atrace
and perfetto will consider the categories and ftrace events listed there.

The file contains a list of categories, and for each category (on the following
lines, indented with one or more spaces of time), a list of ftrace events that
should be enabled when the category is enabled.

Each ftrace event should be a subdirectory in `/sys/kernel/tracing/events/` and
should be of the form `group/event`. Listing a whole group is not supported,
each event needs to be listed explicitly.

It is not an error if an ftrace event is listed in the file, but not present on
the tracing file system.

Example:

```
gfx
 mali/gpu_power_state
 mali/mali_pm_status
thermal_tj
 thermal_exynos/thermal_cpu_pressure
 thermal_exynos/thermal_exynos_arm_update
```

The file lists two categories (`gfx` and `thermal_tj`). When the `gfx` category
is enabled, atrace (or perfetto) will enable
`/sys/kernel/tracing/events/mali/gpu_power_state` and
`/sys/kernel/tracing/events/mali/mali_pm_status`. When the `thermal_tj` category
is enabled, atrace (or perfetto) will enable
`/sys/kernel/tracing/events/thermal_exynos/thermal_cpu_pressure` and
`/sys/kernel/tracing/events/thermal_exynos/thermal_exynos_arm_update`.

Since android 14, if the file `/vendor/etc/atrace/atrace_categories.txt` exists
on the file system, perfetto and atrace do not query the android.hardware.atrace
HAL (which is deprecated).
