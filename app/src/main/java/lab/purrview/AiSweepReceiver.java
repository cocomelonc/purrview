package lab.purrview;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.util.Log;

/**
 * Minimal exported trigger for the tools/ai_mutate.py {@code --sweep} harness.
 *
 * <p>No data from the incoming broadcast is used: it always starts {@link
 * PngDecodeService} against PurrView's own already-private
 * {@code files/purrview-ai.png}, exactly like MainActivity's "Run AI PoC"
 * button. It is a no-op unless the installed build is itself debuggable, so
 * side-loading this APK does not widen it beyond the same run-as-gated,
 * debug-device trust level the rest of the demo already assumes.
 */
public final class AiSweepReceiver extends BroadcastReceiver {
    public static final String ACTION_START = "lab.purrview.action.AI_SWEEP_START";
    private static final String LOG_TAG = "PurrView/PNG";

    @Override public void onReceive(Context context, Intent intent) {
        if ((context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            return;
        }
        Log.i(LOG_TAG, "sweep trigger received; starting AI PoC worker");
        Intent request = new Intent(context, PngDecodeService.class)
                .setAction(PngDecodeService.ACTION_START)
                .putExtra(PngDecodeService.EXTRA_FIXED, false)
                .putExtra(PngDecodeService.EXTRA_PRIVATE_FILE, "purrview-ai.png");
        context.startService(request);
    }
}
