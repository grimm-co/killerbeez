#include <windows.h>
/*
 * Given a ProcessId this function will attempt to determine if it is
 * "stuck" on a modal dialog. These are usualy some sport of error
 * and flow stoppage without a full crash, forcing us to wait for
 * timeout otherwise. We don't read the message, only know that it is
 * there incase the other process hangs. We don't want to get stuck.
 */
BOOL IsProcessInModalDialog(
    DWORD dwTargetProcessId
)
{
    HWND hwndFoundDialog = NULL;
    HWND hwndDialogOwner = NULL;
    DWORD dwThreadId;
    DWORD dwProcessId;
    do
    {
        hwndFoundDialog = FindWindowExA( // Find a "Dialog" class window
            GetDesktopWindow(),
            hwndFoundDialog,
            MAKEINTATOM(32770), // "#32770 (Dialog)"
            NULL
        );
        if ( hwndFoundDialog )
        {
            hwndDialogOwner = GetWindow( hwndFoundDialog, GW_OWNER ); // Fetch it's owner

            if ( !IsWindowEnabled( hwndDialogOwner ) ) // If owner is disabled, possibly modal dialog
            {
                dwThreadId = GetWindowThreadProcessId(
                    hwndDialogOwner,
                    &dwProcessId
                );
                if ( dwProcessId == dwTargetProcessId ) return TRUE;
            }
        }
    } 
    while ( hwndFoundDialog != NULL );

    return FALSE;
}
