package lab.purrview;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.util.Log;

/**
 * Bounded, debuggable-only broadcast triggers for tools/purr_agent.py's live
 * validation methods. It is a second, deliberately small exported surface next
 * to {@link AiSweepReceiver}, at the same trust level: a no-op unless the
 * installed build is itself debuggable, so side-loading this APK never widens
 * it beyond the run-as-gated debug device the demo already assumes.
 *
 * <p>Two actions, neither of which takes an arbitrary path, offset or payload
 * from the incoming broadcast:
 *
 * <ul>
 *   <li>{@code ASLR_SELFCHECK} runs the same {@code dladdr()} self-report the
 *       "ASLR self-check" button runs, in the main app process, logging the
 *       {@code PurrView/ASLR} line so the agent's {@code maps_vs_dladdr} method
 *       can cross-check it against an external {@code /proc/maps} read. No data
 *       from the broadcast is used.</li>
 *   <li>{@code RW_START} starts {@link PngDecodeService}'s read/write primitive
 *       against PurrView's own already-private {@code files/purrview-rw.png},
 *       exactly like the "R/W PoC" buttons. The only value read from the
 *       broadcast is a target that must be exactly {@code "memory"} or
 *       {@code "file"}; anything else falls back to {@code "memory"}.</li>
 * </ul>
 */
public final class LabControlReceiver extends BroadcastReceiver {
    public static final String ACTION_ASLR_SELFCHECK = "lab.purrview.action.ASLR_SELFCHECK";
    public static final String ACTION_RW_START = "lab.purrview.action.RW_START";
    private static final String RW_PRIVATE_FILE = "purrview-rw.png";
    private static final String ASLR_TAG = "PurrView/ASLR";
    private static final String PNG_TAG = "PurrView/PNG";

    static {
        System.loadLibrary("purrview");
    }

    /** Same native self-report as MainActivity; see bridge.c. */
    private native String selfAslr();

    @Override public void onReceive(Context context, Intent intent) {
        if ((context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            return;
        }
        String action = intent.getAction();
        if (ACTION_ASLR_SELFCHECK.equals(action)) {
            Log.i(ASLR_TAG, "self-check trigger received");
            try {
                // selfAslr() logs the PurrView/ASLR base line from native code.
                selfAslr();
            } catch (UnsatisfiedLinkError error) {
                Log.w(ASLR_TAG, "self-check unavailable: " + error.getMessage());
            }
        } else if (ACTION_RW_START.equals(action)) {
            String requested = intent.getStringExtra(PngDecodeService.EXTRA_RW_TARGET);
            String target = "file".equals(requested) ? "file" : "memory";
            Log.i(PNG_TAG, "R/W trigger received; starting R/W worker target=" + target);
            context.startService(new Intent(context, PngDecodeService.class)
                    .setAction(PngDecodeService.ACTION_START)
                    .putExtra(PngDecodeService.EXTRA_RW, true)
                    .putExtra(PngDecodeService.EXTRA_RW_TARGET, target)
                    .putExtra(PngDecodeService.EXTRA_PRIVATE_FILE, RW_PRIVATE_FILE));
        }
    }
}
