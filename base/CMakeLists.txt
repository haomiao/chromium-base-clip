set(my_target base)

set(SRC_GRP_ALLOCATOR
  allocator/partition_allocator/partition_alloc.h
  allocator/partition_allocator/partition_alloc.cc
  allocator/allocator_check.h
  allocator/allocator_check.cc
  allocator/allocator_extension.h
  allocator/allocator_extension.cc
  allocator/partition_allocator/page_allocator.h
  allocator/partition_allocator/page_allocator.cc
  allocator/partition_allocator/address_space_randomization.h
  allocator/partition_allocator/address_space_randomization.cc
  allocator/partition_allocator/partition_bucket.h
  allocator/partition_allocator/partition_bucket.cc
  allocator/partition_allocator/partition_oom.h
  allocator/partition_allocator/partition_oom.cc
  allocator/partition_allocator/partition_page.h
  allocator/partition_allocator/partition_page.cc
  allocator/partition_allocator/partition_root_base.h
  allocator/partition_allocator/partition_root_base.cc
  allocator/partition_allocator/spin_lock.h
  allocator/partition_allocator/spin_lock.cc
)

if(WIN32)
set(SRC_GRP_ALLOCATOR
  ${SRC_GRP_ALLOCATOR}
  allocator/winheap_stubs_win.h
  allocator/winheap_stubs_win.cc
  allocator/allocator_shim_default_dispatch_to_winheap.cc
)
endif()

set(SRC_GRP_TASK_SCHEDULER
  task_scheduler/post_task.h
  task_scheduler/post_task.cc
  task_scheduler/delayed_task_manager.h
  task_scheduler/delayed_task_manager.cc
  task_scheduler/environment_config.h
  task_scheduler/environment_config.cc
  task_scheduler/scheduler_lock_impl.h
  task_scheduler/scheduler_lock_impl.cc
  task_scheduler/lazy_task_runner.h
  task_scheduler/lazy_task_runner.cc
  task_scheduler/priority_queue.h
  task_scheduler/priority_queue.cc
  task_scheduler/scheduler_worker.h
  task_scheduler/scheduler_worker.cc
  task_scheduler/scheduler_single_thread_task_runner_manager.h
  task_scheduler/scheduler_single_thread_task_runner_manager.cc
  task_scheduler/scheduler_worker_pool.h
  task_scheduler/scheduler_worker_pool.cc
  task_scheduler/scheduler_worker_pool_impl.h
  task_scheduler/scheduler_worker_pool_impl.cc
  task_scheduler/scheduler_worker_pool_params.h
  task_scheduler/scheduler_worker_pool_params.cc
  task_scheduler/scheduler_worker_stack.h
  task_scheduler/scheduler_worker_stack.cc
  task_scheduler/scoped_set_task_priority_for_current_thread.h
  task_scheduler/scoped_set_task_priority_for_current_thread.cc
  task_scheduler/sequence.h
  task_scheduler/sequence.cc
  task_scheduler/sequence_sort_key.h
  task_scheduler/sequence_sort_key.cc
  task_scheduler/service_thread.h
  task_scheduler/service_thread.cc
  task_scheduler/task.h
  task_scheduler/task.cc
  task_scheduler/task_scheduler.h
  task_scheduler/task_scheduler.cc
  task_scheduler/task_scheduler_impl.h
  task_scheduler/task_scheduler_impl.cc
  task_scheduler/task_tracker.h
  task_scheduler/task_tracker.cc
  task_scheduler/task_traits.h
  task_scheduler/task_traits.cc
)

if(WIN32)
else()
  list(APPEND SRC_GRP_TASK_SCHEDULER
    task_scheduler/task_tracker_posix.h
    task_scheduler/task_tracker_posix.cc
  )
endif()

set(SRC_GRP_CONTAINERS
  containers/linked_list.h
  containers/mru_cache.h
  containers/small_map.h
  containers/stack_container.h
  containers/adapters.h
  containers/circular_deque.h
  containers/vector_buffer.h
  containers/stack.h
  containers/unique_ptr_adapters.h
)

set(SRC_GRP_MEMORY
  memory/aligned_memory.h
  memory/aligned_memory.cc
  memory/weak_ptr.h
  memory/weak_ptr.cc
  memory/ref_counted.h
  memory/ref_counted.cc
  memory/singleton.h
  memory/raw_scoped_refptr_mismatch_checker.h
  memory/memory_pressure_listener.cc
  memory/memory_pressure_listener.h
  memory/ref_counted_memory.cc
  memory/ref_counted_memory.h
  memory/scoped_policy.h
  memory/shared_memory.h
  memory/shared_memory_handle.h
  memory/shared_memory_handle.cc
  memory/shared_memory_tracker.h
  memory/shared_memory_tracker.cc
  memory/shared_memory_mapping.h
  memory/shared_memory_mapping.cc
  memory/read_only_shared_memory_region.h
  memory/read_only_shared_memory_region.cc
  memory/platform_shared_memory_region.h
  memory/platform_shared_memory_region.cc
)

if(WIN32)
  list(APPEND SRC_GRP_MEMORY
    memory/shared_memory_win.cc
    memory/shared_memory_handle_win.cc
    memory/platform_shared_memory_region_win.cc
  )
else()
  list(APPEND SRC_GRP_MEMORY
    memory/shared_memory_helper.h
	  memory/shared_memory_helper.cc
    memory/shared_memory_posix.cc
    memory/protected_memory_posix.cc
  )
  if(ANDROID)
    list(APPEND SRC_GRP_MEMORY
      third_party/ashmem/ashmem.h
      third_party/ashmem/ashmem-dev.c
      memory/platform_shared_memory_region_android.cc
      memory/shared_memory_android.cc
      memory/shared_memory_handle_android.cc
    )
  else()
    list(APPEND SRC_GRP_MEMORY
      memory/platform_shared_memory_region_posix.cc  
      memory/shared_memory_handle_posix.cc
    )
  endif()
endif()

set(SRC_GRP_DEBUG
  debug/alias.h
  debug/alias.cc
  debug/debugger.h
  debug/debugger.cc
  debug/stack_trace.h
  debug/stack_trace.cc
  debug/profiler.h
  debug/profiler.cc
  debug/crash_logging.cc
  debug/crash_logging.h
  debug/dump_without_crashing.cc
  debug/dump_without_crashing.h
  debug/leak_annotations.h
  debug/leak_tracker.h
  debug/task_annotator.cc
  debug/task_annotator.h
  debug/activity_tracker.h
  debug/activity_tracker.cc
  debug/activity_analyzer.h
  debug/activity_analyzer.cc
)

if(WIN32)
  list(APPEND SRC_GRP_DEBUG
    debug/debugger_win.cc
    debug/stack_trace_win.cc
    debug/gdi_debug_util_win.cc
    debug/gdi_debug_util_win.h
  )
else()
  list(APPEND SRC_GRP_DEBUG
    debug/debugger_posix.cc
    debug/proc_maps_linux.h
    debug/proc_maps_linux.cc
  )
  if(ANDROID)
   list(APPEND SRC_GRP_DEBUG
    debug/stack_trace_android.cc
  )
  else()
  list(APPEND SRC_GRP_DEBUG
    debug/stack_trace_posix.cc
    debug/elf_reader_linux.cc
    debug/elf_reader_linux.h
    debug/proc_maps_linux.cc
    debug/proc_maps_linux.h
  ) 
  endif()
endif()

set(SRC_GRP_FILES
  files/file.h
  files/file.cc
  files/file_tracing.h
  files/file_tracing.cc
  files/file_enumerator.h
  files/file_enumerator.cc
  files/file_path.h
  files/file_path.cc
  files/file_path_constants.cc
  files/file_path_watcher.h
  files/file_path_watcher.cc
  files/important_file_writer.h
  files/important_file_writer.cc
  files/memory_mapped_file.h
  files/memory_mapped_file.cc
  files/scoped_temp_dir.h
  files/scoped_temp_dir.cc
  files/file_util.h
  files/file_util.cc
  files/scoped_file.h
  files/scoped_file.cc
  files/file_proxy.h
  files/file_proxy.cc
  files/dir_reader_fallback.h
)

if(WIN32)
  list(APPEND SRC_GRP_FILES
    files/file_win.cc
    files/file_enumerator_win.cc
    files/file_path_watcher_win.cc
    files/memory_mapped_file_win.cc
    files/file_util_win.cc
  )
else()
  list(APPEND SRC_GRP_FILES
    files/file_posix.cc
    files/file_enumerator_posix.cc
    files/memory_mapped_file_posix.cc
    files/file_util_posix.cc
    files/dir_reader_posix.h
    files/file_descriptor_watcher_posix.h
    files/file_descriptor_watcher_posix.cc
  )
  if(ANDROID)
    list(APPEND SRC_GRP_FILES
      files/file_util_android.cc
    )
  else()
    list(APPEND SRC_GRP_FILES
      files/file_path_watcher_linux.cc
      files/file_util_linux.cc
      files/dir_reader_linux.h
    )
  endif()
endif()

set(SRC_GRP_MESSAGE_LOOP
  message_loop/message_loop.h
  message_loop/message_loop.cc
  message_loop/message_loop_current.h
  message_loop/message_loop_current.cc
  message_loop/message_pump.h
  message_loop/message_pump.cc
  message_loop/message_pump_default.h
  message_loop/message_pump_default.cc
  message_loop/incoming_task_queue.h
  message_loop/incoming_task_queue.cc
  message_loop/message_loop_task_runner.h
  message_loop/message_loop_task_runner.cc
  message_loop/timer_slack.h
)

if(WIN32)
 list(APPEND SRC_GRP_MESSAGE_LOOP
    message_loop/message_pump_win.h
    message_loop/message_pump_win.cc
 )
else()
  list(APPEND SRC_GRP_MESSAGE_LOOP
    message_loop/message_pump_libevent.h
    message_loop/message_pump_libevent.cc
    message_loop/watchable_io_message_pump_posix.h
    message_loop/watchable_io_message_pump_posix.cc
  )
  if(ANDROID)
   list(APPEND SRC_GRP_MESSAGE_LOOP
    message_loop/message_pump_android.h
    message_loop/message_pump_android.cc
  ) 
  endif()
endif()

set(SRC_GRP_METRICS
  metrics/histogram.h
  metrics/histogram.cc
  metrics/histogram_functions.h
  metrics/histogram_functions.cc
  metrics/histogram_base.h
  metrics/histogram_base.cc
  metrics/histogram_samples.h
  metrics/histogram_samples.cc
  metrics/metrics_hashes.h
  metrics/metrics_hashes.cc
  metrics/dummy_histogram.h
  metrics/dummy_histogram.cc
  metrics/persistent_histogram_allocator.h
  metrics/persistent_histogram_allocator.cc
  metrics/sample_vector.h
  metrics/sample_vector.cc
  metrics/sample_map.h
  metrics/sample_map.cc
  metrics/statistics_recorder.h
  metrics/statistics_recorder.cc
  metrics/sparse_histogram.h
  metrics/sparse_histogram.cc
  metrics/single_sample_metrics.h
  metrics/single_sample_metrics.cc
  metrics/user_metrics.h
  metrics/user_metrics.cc
  metrics/persistent_histogram_storage.h
  metrics/persistent_histogram_storage.cc
  metrics/histogram_delta_serialization.h
  metrics/histogram_delta_serialization.cc
  metrics/field_trial.h
  metrics/field_trial.cc
  metrics/field_trial_param_associator.h
  metrics/field_trial_param_associator.cc
  metrics/field_trial_params.h
  metrics/field_trial_params.cc
  metrics/persistent_memory_allocator.h
  metrics/persistent_memory_allocator.cc
  metrics/persistent_sample_map.h
  metrics/persistent_sample_map.cc
  metrics/persistent_histogram_storage.h
  metrics/persistent_histogram_storage.cc
  metrics/bucket_ranges.h
  metrics/bucket_ranges.cc
  metrics/histogram_snapshot_manager.h
  metrics/histogram_snapshot_manager.cc
)

set(SRC_GRP_PROFILER
  
)

set(SRC_GRP_TRACE_EVENT
  trace_event/memory_allocator_dump.h
  trace_event/memory_allocator_dump.cc
  trace_event/memory_peak_detector.h
  trace_event/memory_peak_detector.cc
  trace_event/process_memory_dump.h
  trace_event/process_memory_dump.cc
  trace_event/trace_buffer.h
  trace_event/trace_buffer.cc
  trace_event/trace_config.h
  trace_event/trace_config.cc
  trace_event/trace_config_category_filter.h
  trace_event/trace_config_category_filter.cc
  trace_event/trace_event_argument.h
  trace_event/trace_event_argument.cc
  trace_event/trace_event_filter.h
  trace_event/trace_event_filter.cc
  trace_event/trace_event_impl.h
  trace_event/trace_event_impl.cc
  trace_event/trace_event_memory_overhead.h
  trace_event/trace_event_memory_overhead.cc
  trace_event/trace_event_system_stats_monitor.h
  trace_event/trace_event_system_stats_monitor.cc
  trace_event/trace_log.h
  trace_event/trace_log.cc
  trace_event/trace_log_constants.cc
  trace_event/tracing_agent.h
  trace_event/tracing_agent.cc
  trace_event/memory_dump_request_args.h
  trace_event/memory_dump_request_args.cc
  trace_event/memory_dump_scheduler.h
  trace_event/memory_dump_scheduler.cc
  trace_event/memory_dump_manager.h
  trace_event/memory_dump_manager.cc
  trace_event/memory_dump_provider_info.h
  trace_event/memory_dump_provider_info.cc
  trace_event/memory_dump_request_args.h
  trace_event/memory_dump_request_args.cc
  trace_event/heap_profiler_allocation_context.h
  trace_event/heap_profiler_allocation_context.cc
  trace_event/heap_profiler_allocation_context_tracker.h
  trace_event/heap_profiler_allocation_context_tracker.cc
  trace_event/category_registry.h
  trace_event/category_registry.cc
  trace_event/malloc_dump_provider.h
  trace_event/malloc_dump_provider.cc
  trace_event/memory_infra_background_whitelist.h
  trace_event/memory_infra_background_whitelist.cc
  trace_event/heap_profiler_stack_frame_deduplicator.h
  trace_event/heap_profiler_stack_frame_deduplicator.cc
  trace_event/heap_profiler_serialization_state.h
  trace_event/heap_profiler_serialization_state.cc
  trace_event/memory_allocator_dump_guid.h
  trace_event/memory_allocator_dump_guid.cc
  trace_event/event_name_filter.h
  trace_event/event_name_filter.cc
  trace_event/heap_profiler_event_filter.h
  trace_event/heap_profiler_event_filter.cc
  trace_event/heap_profiler_heap_dump_writer.h
  trace_event/heap_profiler_heap_dump_writer.cc
  trace_event/heap_profiler_type_name_deduplicator.h
  trace_event/heap_profiler_type_name_deduplicator.cc
  trace_event/memory_usage_estimator.h
  trace_event/memory_usage_estimator.cc
)

if(WIN32)
list(APPEND SRC_GRP_TRACE_EVENT
  trace_event/trace_event_etw_export_win.h
  trace_event/trace_event_etw_export_win.cc
)
else()
  if(ANDROID)
  list(APPEND SRC_GRP_TRACE_EVENT
    trace_event/trace_event_android.cc
    trace_event/java_heap_dump_provider_android.h
    trace_event/java_heap_dump_provider_android.cc
  )
  endif()
endif()


set(SRC_GRP_PROCESS
  process/kill.h
  process/kill.cc
  process/launch.h
  process/launch.cc
  process/process_iterator.h
  process/process_iterator.cc
  process/memory.h
  #process/memory.cc
  process/process_handle.h
  process/process_handle.cc
  process/process.h
  process/process_info.h
  process/process_metrics.h
  process/process_metrics.cc
)

if(WIN32)
  list(APPEND SRC_GRP_PROCESS
    process/kill_win.cc
    process/process_iterator_win.cc
    process/launch_win.cc
    process/memory_win.cc
    process/process_win.cc
    process/process_metrics_win.cc
    process/process_info_win.cc
    process/process_handle_win.cc
  )
else()
  list(APPEND SRC_GRP_PROCESS
    process/internal_linux.h
    process/internal_linux.cc
    process/kill_posix.cc
    process/launch_posix.cc
    #process/memory_linux.cc
    process/memory_stubs.cc
    process/process_metrics_linux.cc
    process/process_metrics_posix.cc
    process/process_info_linux.cc
    process/process_posix.cc
    process/process_handle_linux.cc
    process/process_handle_posix.cc
    process/process_iterator_linux.cc
  )
endif()

set(SRC_GRP_POWER_MONITOR
  power_monitor/power_monitor.h
  power_monitor/power_monitor.cc
  power_monitor/power_monitor_device_source.h
  power_monitor/power_monitor_device_source.cc
  power_monitor/power_monitor_source.h
  power_monitor/power_monitor_source.cc
  power_monitor/power_observer.h
)

if(WIN32)
  list(APPEND SRC_GRP_POWER_MONITOR
    power_monitor/power_monitor_device_source_win.cc
  )
else()
  list(APPEND SRC_GRP_POWER_MONITOR
    power_monitor/power_monitor_device_source_stub.cc
  )
endif()

source_group("SRC_GRP_POWER_MONITOR"
  FILES
    ${SRC_GRP_TEST}
)

set(SRC_GRP_STRINGS
  strings/string_number_conversions.h
  strings/string_number_conversions.cc
  strings/string_piece.h
  strings/string_piece.cc
  strings/string_split.h
  strings/string_split.cc
  strings/pattern.h
  strings/pattern.cc
  strings/string_util.h
  strings/string_util.cc
  strings/string_tokenizer.h
  strings/string16.h
  strings/utf_string_conversion_utils.h
  strings/utf_string_conversion_utils.cc
  strings/utf_string_conversions.h
  strings/utf_string_conversions.cc
  strings/safe_sprintf.h
  strings/safe_sprintf.cc
  strings/stringprintf.h
  strings/stringprintf.cc
  third_party/icu/icu_utf.h
  third_party/icu/icu_utf.cc
  strings/string_util_constants.cc
  strings/stringize_macros.h
  strings/latin1_string_conversions.cc
  strings/latin1_string_conversions.h
  strings/nullable_string16.cc
  strings/nullable_string16.h
  third_party/dmg_fp/dmg_fp.h
  third_party/dmg_fp/dtoa_wrapper.cc
  third_party/dmg_fp/g_fmt.cc
)

if(WIN32)
  list(APPEND SRC_GRP_STRINGS
    strings/sys_string_conversions_win.cc
  )
else()
  list(APPEND SRC_GRP_STRINGS
    strings/string16.cc
    strings/sys_string_conversions_posix.cc
  )
endif()

set(SRC_GRP_SYNCHROIZATION
  synchronization/cancellation_flag.h
  synchronization/condition_variable.h
  synchronization/lock.h
  synchronization/lock.cc
  synchronization/lock_impl.h
  synchronization/waitable_event.h
  synchronization/spin_wait.h
  synchronization/waitable_event_watcher.h
  synchronization/atomic_flag.h
  synchronization/atomic_flag.cc
)

if(WIN32)
  list(APPEND SRC_GRP_SYNCHROIZATION
    synchronization/lock_impl_win.cc
    synchronization/condition_variable_win.cc
    synchronization/waitable_event_win.cc
    synchronization/waitable_event_watcher_win.cc
  )
else()
  list(APPEND SRC_GRP_SYNCHROIZATION
    synchronization/lock_impl_posix.cc
    synchronization/condition_variable_posix.cc
    synchronization/waitable_event_posix.cc
    synchronization/waitable_event_watcher_posix.cc
  )
endif()

set(SRC_GRP_THREADING
  threading/platform_thread.h
  threading/post_task_and_reply_impl.h
  threading/post_task_and_reply_impl.cc
  threading/simple_thread.h
  threading/simple_thread.cc
  threading/thread.h
  threading/thread.cc
  threading/thread_checker.h
  threading/thread_checker_impl.h
  threading/thread_checker_impl.cc
  threading/thread_collision_warner.h
  threading/thread_collision_warner.cc
  threading/thread_id_name_manager.h
  threading/thread_id_name_manager.cc
  threading/thread_local.h
  threading/thread_local_storage.h
  threading/thread_local_storage.cc
  threading/thread_restrictions.h
  threading/thread_restrictions.cc
  threading/watchdog.h
  threading/watchdog.cc
  threading/sequence_local_storage_map.h
  threading/sequence_local_storage_map.cc
  threading/sequence_local_storage_slot.h
  threading/sequence_local_storage_slot.cc
  threading/sequenced_task_runner_handle.h
  threading/sequenced_task_runner_handle.cc
  threading/thread_task_runner_handle.h
  threading/thread_task_runner_handle.cc
  threading/scoped_blocking_call.h
  threading/scoped_blocking_call.cc
)

if(WIN32)
  list(APPEND SRC_GRP_THREADING
    threading/platform_thread_win.cc
    threading/thread_local_storage_win.cc
  )
else()
  list(APPEND SRC_GRP_THREADING
    threading/platform_thread_posix.cc
    threading/platform_thread_internal_posix.h
    threading/platform_thread_internal_posix.cc
    threading/thread_local_storage_posix.cc
  )
  if(ANDROID)
  list(APPEND SRC_GRP_THREADING
    threading/platform_thread_android.cc
  )
  else()
   list(APPEND SRC_GRP_THREADING
    threading/platform_thread_linux.cc
  )
  endif()
endif()



set(SRC_GRP_JSON
  json/json_file_value_serializer.h
  json/json_file_value_serializer.cc
  json/json_parser.h
  json/json_parser.cc
  json/json_reader.h
  json/json_reader.cc
  json/json_string_value_serializer.h
  json/json_string_value_serializer.cc
  json/json_writer.h
  json/json_writer.cc
  json/string_escape.h
  json/string_escape.cc
  json/json_value_converter.h
)

set(SRC_GRP_NSPR
  third_party/nspr/prtime.h
  third_party/nspr/prtime.cc
)

set(SRC_GRP_CITYHASH
  cityhash/city.h
  cityhash/city.cc
  cityhash/citycrc.h
)

set(SRC_GRP_TIME
  time/clock.h
  time/clock.cc
  time/default_clock.h
  time/default_clock.cc
  time/default_tick_clock.h
  time/default_tick_clock.cc
  time/tick_clock.h
  time/tick_clock.cc
  time/time.h
  time/time.cc
  time/time_to_iso8601.h
  time/time_to_iso8601.cc
)

if(WIN32)
  list(APPEND SRC_GRP_TIME
    time/time_win.cc
  )
else()
  list(APPEND SRC_GRP_TIME
    time/time_now_posix.cc
    time/time_exploded_posix.cc
    time/time_conversion_posix.cc
  )
endif()

set(SRC_GRP_TIMER
  timer/elapsed_timer.h
  timer/elapsed_timer.cc
  timer/hi_res_timer_manager.h
  timer/timer.h
  timer/timer.cc
  timer/mock_timer.h
  timer/mock_timer.cc
)

if(WIN32)
set(SRC_GRP_TIMER
  ${SRC_GRP_TIMER}
  timer/hi_res_timer_manager_win.cc
)
endif()

if(WIN32)
set(SRC_GRP_WIN
  win/object_watcher.h
  win/object_watcher.cc
  win/pe_image.h
  win/pe_image.cc
  win/scoped_co_mem.h
  win/scoped_handle.h
  win/scoped_handle.cc
  win/scoped_handle_verifier.h
  win/scoped_handle_verifier.cc
  win/wrapped_window_proc.h
  win/wrapped_window_proc.cc
  win/scoped_process_information.h
  win/scoped_process_information.cc
  win/startup_information.h
  win/startup_information.cc
  win/registry.h
  win/registry.cc
  win/windows_version.h
  win/windows_version.cc
  win/scoped_com_initializer.h
  win/scoped_com_initializer.cc
  win/dllmain.cc
  win/iat_patch_function.cc
  win/iat_patch_function.h
  win/iunknown_impl.cc
  win/iunknown_impl.h
  win/message_window.cc
  win/message_window.h
  win/resource_util.cc
  win/resource_util.h
  win/scoped_bstr.cc
  win/scoped_bstr.h
  win/scoped_gdi_object.h
  win/scoped_hdc.h
  win/scoped_hglobal.h
  win/scoped_hstring.h
  win/scoped_hstring.cc
  win/scoped_propvariant.h
  win/scoped_select_object.h
  win/scoped_variant.cc
  win/scoped_variant.h
  win/win_util.cc
  win/win_util.h
  win/scoped_winrt_initializer.cc
  win/scoped_winrt_initializer.h
  win/com_init_util.cc
  win/com_init_util.h
  win/core_winrt_util.cc
  win/core_winrt_util.h
  win/com_init_check_hook.cc
  win/com_init_check_hook.h
  win/patch_util.cc
  win/patch_util.h
)
endif()

set(SRC_GRP_BASE
  at_exit.h
  at_exit.cc
  atomic_ref_count.h
  atomic_sequence_num.h
  atomicops.h
  base_export.h
  base_paths.h
  base_paths.cc
  base_switches.h
  base_switches.cc
  bind.h
  bind_helpers.h
  callback.h
  callback_forward.h
  callback_helpers.h
  callback_helpers.cc
  callback_internal.h
  callback_internal.cc
  compiler_specific.h
  command_line.h
  command_line.cc
  cpu.h
  cpu.cc
  critical_closure.h
  environment.h
  environment.cc
  guid.h
  guid.cc
  hash.h
  hash.cc
  feature_list.h
  feature_list.cc
  lazy_instance.h
  logging.h
  logging.cc
  location.h
  location.cc
  macros.h
  md5.h
  md5.cc
  sequence_token.h
  sequence_token.cc
  native_library.h
  native_library.cc
  lazy_instance_helpers.h
  lazy_instance_helpers.cc
  observer_list.h
  observer_list_threadsafe.h
  observer_list_threadsafe.cc
  pending_task.h
  pending_task.cc
  path_service.h
  path_service.cc
  pickle.h
  pickle.cc
  rand_util.h
  rand_util.cc
  run_loop.h
  run_loop.cc
  sequence_checker.h
  sequence_checker_impl.h
  sequence_checker_impl.cc
  sequenced_task_runner.h
  sequenced_task_runner.cc
  sequenced_task_runner_helpers.h
  single_thread_task_runner.h
  stl_util.h
  sync_socket.h
  task_runner.h
  task_runner.cc
  task_runner_util.h
  template_util.h
  tuple.h
  values.h
  values.cc
  sys_info.h
  sys_info.cc
  vlog.h
  vlog.cc
  auto_reset.h
  base64.cc
  base64.h
  third_party/modp_b64/modp_b64.cc
  bits.h
  callback_list.h
  cancelable_callback.h
  scoped_native_library.cc
  scoped_native_library.h
  scoped_observer.h
  sha1.h
  sha1.cc
  value_iterators.h
  value_iterators.cc
  unguessable_token.h
  unguessable_token.cc
  sys_byteorder.h
  value_conversions.cc
  value_conversions.h
  barrier_closure.cc
  barrier_closure.h
  big_endian.cc
  big_endian.h
  build_time.cc
  build_time.h
  deferred_sequenced_task_runner.cc
  deferred_sequenced_task_runner.h
  file_version_info.h
  format_macros.h
  scoped_generic.h
  supports_user_data.cc
  supports_user_data.h
  version.cc
  version.h
  ini_parser.h
  ini_parser.cc
  third_party/superfasthash/superfasthash.c
  auto_thread.cc
  auto_thread.h
  auto_thread_task_runner.cc
  auto_thread_task_runner.h
)

if(WIN32)
  list(APPEND SRC_GRP_BASE
    base_paths_win.h
    base_paths_win.cc
    atomicops_internals_x86_msvc.h
    rand_util_win.cc
    native_library_win.cc
    sync_socket_win.cc
    file_version_info_win.cc
    file_version_info_win.h
    sys_info_win.cc
  )
else()
  list(APPEND SRC_GRP_BASE
    base_paths_posix.h
    base_paths_posix.cc
    file_descriptor_posix.h
    native_library_posix.cc
    rand_util_posix.cc
    sync_socket_posix.cc
   
    sys_info_posix.cc
  )
  if(ANDROID)
    list(APPEND SRC_GRP_BASE
      base_paths_android.h
      base_paths_android.cc
      sys_info_linux.cc
      sys_info_android.cc
    )
  else()
    list(APPEND SRC_GRP_BASE
        sys_info_linux.cc
      )
  endif()
  # posix
  list(APPEND SRC_GRP_BASE
    posix/eintr_wrapper.h
    posix/file_descriptor_shuffle.cc
    posix/file_descriptor_shuffle.h
    posix/global_descriptors.h
    posix/global_descriptors.cc
    posix/safe_strerror.h
    posix/safe_strerror.cc
    posix/unix_domain_socket.h
    posix/unix_domain_socket.cc
  )
  # nix
  list(APPEND SRC_GRP_BASE
    nix/mime_util_xdg.cc
    nix/mime_util_xdg.h
    nix/xdg_util.h
    nix/xdg_util.cc

    third_party/xdg_user_dirs/xdg_user_dir_lookup.h
    third_party/xdg_user_dirs/xdg_user_dir_lookup.cc
  )
endif()

if(ANDROID)
list(APPEND SRC_GRP_ANDROID
    android/build_info.h
    android/build_info.cc
    android/jni_android.h
    android/jni_android.cc
    android/jni_string.h
    android/jni_string.cc
    android/jni_array.h
    android/jni_array.cc
    android/scoped_java_ref.h
    android/scoped_java_ref.cc
    android/path_utils.h
    android/path_utils.cc
    android/content_uri_utils.h
    android/content_uri_utils.cc
    android/java_runtime.h
    android/java_runtime.cc
    android/sys_utils.h
    android/sys_utils.cc
    os_compat_android.h
    os_compat_android.cc
  )
endif()

set(SRC_GRP_TEST
  test/scoped_task_environment.cc
  test/scoped_task_environment.h
  test/test_mock_time_task_runner.cc
  test/test_mock_time_task_runner.h
  test/test_pending_task.cc
  test/test_pending_task.h
)

set(LIBRARY_SRCS
  ${SRC_GRP_BASE}
  ${SRC_GRP_CONTAINERS}
  ${SRC_GRP_FILES}
  ${SRC_GRP_MEMORY}
  ${SRC_GRP_DEBUG}
  ${SRC_GRP_MESSAGE_LOOP}
  ${SRC_GRP_PROFILER}
  ${SRC_GRP_STRINGS}
  ${SRC_GRP_PROCESS}
  ${SRC_GRP_SYNCHROIZATION}
  ${SRC_GRP_THREADING}
  ${SRC_GRP_TIME}
  ${SRC_GRP_TIMER}
  ${SRC_GRP_NSPR}
  ${SRC_GRP_JSON}
  ${SRC_GRP_METRICS}
  ${SRC_GRP_TRACE_EVENT}
  ${SRC_GRP_ALLOCATOR}
  ${SRC_GRP_TASK_SCHEDULER}
  ${SRC_GRP_TEST}
  ${SRC_GRP_CITYHASH}
  ${SRC_GRP_ANDROID}
  ${SRC_GRP_POWER_MONITOR}
)

if(WIN32)
  list(APPEND LIBRARY_SRCS
    ${SRC_GRP_WIN}
  )
endif()

source_group("cityhash"
  FILES
    ${SRC_GRP_CITYHASH}
)

source_group("task_scheduler"
  FILES
    ${SRC_GRP_TASK_SCHEDULER}
)

source_group("allocator"
  FILES
    ${SRC_GRP_ALLOCATOR}
)

source_group("trace_event"
  FILES
    ${SRC_GRP_TRACE_EVENT}
)

source_group("json"
  FILES
    ${SRC_GRP_JSON}
)

source_group("containers"
  FILES
    ${SRC_GRP_CONTAINERS}
)

source_group("memory"
  FILES
    ${SRC_GRP_MEMORY}
)

source_group("files"
  FILES
    ${SRC_GRP_FILES}
)

source_group("debug"
  FILES
    ${SRC_GRP_DEBUG}
)

source_group("message_loop"
  FILES
    ${SRC_GRP_MESSAGE_LOOP}
)

source_group("profiler"
  FILES
    ${SRC_GRP_PROFILER}
)

source_group("strings"
  FILES
    ${SRC_GRP_STRINGS}
)

source_group("process"
  FILES
    ${SRC_GRP_PROCESS}
)

source_group("synchronization"
  FILES
    ${SRC_GRP_SYNCHROIZATION}
)

source_group("threading"
  FILES
    ${SRC_GRP_THREADING}
)

source_group("time"
  FILES
    ${SRC_GRP_TIME}
)

source_group("timer"
  FILES
    ${SRC_GRP_TIMER}
)

if(WIN32)
source_group("win"
  FILES
    ${SRC_GRP_WIN}
)
endif()

source_group("nspr"
  FILES
    ${SRC_GRP_NSPR}
)

source_group("test"
  FILES
    ${SRC_GRP_TEST}
)

include_directories(
  .
  ${CMAKE_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/base/breakpad
)

if(ANDROID)
  add_definitions(-D__STDC_FORMAT_MACROS)
  link_libraries(log)
endif()

add_definitions(-DNOMINMAX -DNO_TCMALLOC -D_HAS_EXCEPTIONS=0)

if (BUILD_STATIC_LIBS)
  add_library(${my_target} STATIC
    ${LIBRARY_SRCS}
  )
else()
  add_library(${my_target} SHARED
    ${LIBRARY_SRCS}
  )
endif()

SET_COMMON_TARGET_PROPERTIES(${my_target})
if (BUILD_STATIC_LIBS)
else()
  target_compile_definitions(${my_target} 
    PUBLIC COMPONENT_BUILD
    PRIVATE BASE_IMPLEMENTATION
  )
endif()

if(WIN32)
  target_link_libraries(${my_target} 
  advapi32
  iphlpapi
  shell32
  user32
  Shlwapi
  Propsys
  Setupapi
  )
else()
  target_link_libraries(${my_target} m dl pthread)
  add_subdirectory(third_party/libevent)
  target_link_libraries(${my_target}
    libevent
  )
endif()



if (CMAKE_CXX_FLAGS MATCHES "/EHsc ")
  string(REPLACE "/EHsc" "/EHs-c-" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  message(STATUS "CMAKE_CXX_FLAGS matches /EHsc before end of string --replaced...")
  message(STATUS "")
endif()

if(CMAKE_CXX_FLAGS MATCHES "/EHsc$")
  string(REPLACE "/EHsc" "/EHs-c-" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  message(STATUS "CMAKE_CXX_FLAGS matches /EHsc at end of string --replaced...")
  message(STATUS "")
endif()

message(STATUS "CMAKE_CXX_FLAGS after possible REPLACE operation:")
message(STATUS "CMAKE_CXX_FLAGS='${CMAKE_CXX_FLAGS}'")
message(STATUS "")

#add_subdirectory(unittest)
