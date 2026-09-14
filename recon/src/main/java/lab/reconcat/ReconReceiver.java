package lab.reconcat;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.util.Log;

/**
 * Exported adb trigger for tools/ai_mutate.py: logs this device's own public
 * Build.* fields so the host-side tool can read real recon out of logcat
 * instead of a hand-typed --profile placeholder. No data from the incoming
 * broadcast is used, and it is a no-op unless this build is itself
 * debuggable.
 */
public final class ReconReceiver extends BroadcastReceiver {
    public static final String ACTION_DUMP = "lab.reconcat.action.DUMP_RECON";
    private static final String LOG_TAG = "ReconCat";

    @Override public void onReceive(Context context, Intent intent) {
        if ((context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            return;
        }
        if (!ACTION_DUMP.equals(intent.getAction())) {
            return;
        }
        Log.i(LOG_TAG, "RECON " + DeviceRecon.snapshotJson());
    }
}
