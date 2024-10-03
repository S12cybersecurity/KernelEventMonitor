# KernelEventMonitor
Monitoring  Process Creation/Termination, Thread Creation/Termination and Image Load Notifications from a Kernel Driver

KernelEventMonitor is a Windows Kernel Driver designed to monitor key system events such as:

    Process creation and termination.
    Thread creation and termination.
    Image loading into processes (DLLs, EXEs).

These events are captured using kernel-mode notification routines, and relevant information is logged via the DbgPrintEx function for debugging purposes.
Features

    Process Event Monitoring: Detects and logs the creation and termination of processes.
    Thread Event Monitoring: Detects and logs the creation and termination of threads within processes.
    Image Load Monitoring: Logs the loading of images (such as executables or DLLs) into processes.

Requirements

    Windows operating system
    Windows Driver Kit (WDK)
    Visual Studio (for building the driver)
    Test machine capable of running drivers

Installation

    Build the Driver:
        Open the project in Visual Studio.
        Build the driver using the appropriate configuration (e.g., x64 Debug or x64 Release).

    Install the Driver:
        Use a tool like sc.exe or any driver installation tool to load the driver into the system.
        Example command to load the driver:
        
          sc create KernelEventMonitor type= kernel binPath= "C:\Path\To\Driver\KernelEventMonitor.sys"
          sc start KernelEventMonitor

        Monitor the Output:
        Use DebugView or any other tool that captures kernel-level debug messages to monitor the output of the driver.
        You should see log messages regarding process, thread, and image load events.

Code Breakdown
Driver Entry (DriverEntry)

The entry point for the driver:

    Creates a device object (\Device\EventMonitor).
    Creates a symbolic link (\DosDevices\EventMonitor).
    Registers notification routines to monitor process, thread, and image load events.
    Handles driver unloading via UnloadDriver.

Notification Routines

    Process Events:
        ownCreateProcessNotifyRoutine: Logs process creation and termination.
        Registered with PsSetCreateProcessNotifyRoutine.

    Thread Events:
        ownCreateThreadNotifyRoutine: Logs thread creation and termination within processes.
        Registered with PsSetCreateThreadNotifyRoutine.

    Image Load Events:
        ownLoadImageNotifyRoutine: Logs when images (such as DLLs or EXEs) are loaded into processes.
        Registered with PsSetLoadImageNotifyRoutine.

Unloading the Driver (UnloadDriver)

    Deletes the device and symbolic link created during the driver's initialization.
    Stops monitoring events when the driver is unloaded.

Debugging & Logging

To view the event logs produced by this driver:

    Use DebugView from Sysinternals or any tool that can capture DbgPrintEx output.
    The driver logs messages with the severity level set to DPFLTR_ERROR_LEVEL, which can be viewed during the driver's execution.
        
