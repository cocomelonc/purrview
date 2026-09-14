package lab.purrview;

import android.content.Intent;
import android.util.Log;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/** PurrView-owned PNG parser worker used for the conference reproducer. */
public final class PngDecodeService extends FixtureDecodeService {
    public static final String ACTION_START = "lab.purrview.action.PNG_START";
    public static final String ACTION_RESULT = "lab.purrview.action.PNG_RESULT";
    public static final String EXTRA_ASSET = "asset";
    /** Fixed app-private name used by tools/ai_mutate.py; no arbitrary paths. */
    public static final String EXTRA_PRIVATE_FILE = "private_file";
    public static final String EXTRA_FIXED = "fixed";
    /** Selects the R/W primitive demo (decodePngRw/decodePngRwFile) instead of decodePng. */
    public static final String EXTRA_RW = "rw";
    /** "memory" (default, heap companion buffer) or "file" (companion file in getFilesDir()). */
    public static final String EXTRA_RW_TARGET = "rw_target";
    /** Fixed app-private name used by the R/W primitive demo; no arbitrary paths. */
    private static final String RW_PRIVATE_FILE = "purrview-rw.png";
    private static final int MAX_INPUT = 128 * 1024;
    private static final String LOG_TAG = "PurrView/PNG";

    static {
        System.loadLibrary("purrview");
    }

    public PngDecodeService() {
        super(ACTION_RESULT, MAX_INPUT);
    }

    private native String decodePng(byte[] input, boolean fixed);
    private native String decodePngRw(byte[] input);
    private native String decodePngRwFile(byte[] input, String filesDir);

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || !ACTION_START.equals(intent.getAction())) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        String asset = intent.getStringExtra(EXTRA_ASSET);
        String privateFile = intent.getStringExtra(EXTRA_PRIVATE_FILE);
        boolean rw = intent.getBooleanExtra(EXTRA_RW, false);
        boolean bundled = !rw && "purrview-oob.png".equals(asset) && privateFile == null;
        boolean generated = !rw && asset == null && "purrview-ai.png".equals(privateFile);
        boolean rwGenerated = rw && asset == null && RW_PRIVATE_FILE.equals(privateFile);
        if (!bundled && !generated && !rwGenerated) {
            publish("REJECTED | unknown PNG fixture");
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        boolean fixed = intent.getBooleanExtra(EXTRA_FIXED, false);
        boolean rwFile = rwGenerated && "file".equals(intent.getStringExtra(EXTRA_RW_TARGET));
        String mode = rwGenerated ? (rwFile ? "R/W PoC (file)" : "R/W PoC (memory)")
                : fixed ? "fixed" : "PoC";
        publish("WORKER STARTED | PNG parser | " + mode);
        String fixtureLabel = bundled ? asset : "files/" + privateFile;
        Log.i(LOG_TAG, "worker started in :png_decoder fixture=" + fixtureLabel
                + " mode=" + mode);
        try (InputStream input = bundled
                ? getAssets().open(asset)
                : new FileInputStream(new File(getFilesDir(), privateFile))) {
            byte[] bytes = readBounded(input);
            Log.i(LOG_TAG, "fixture loaded: bytes=" + bytes.length + " source=" + fixtureLabel
                    + "; invoking PurrView parser");
            // Mark the one-shot service finished before entering the PoC. If the
            // native worker aborts, Android will not redeliver this start request.
            stopSelf(startId);
            String result = !rwGenerated ? decodePng(bytes, fixed)
                    : rwFile ? decodePngRwFile(bytes, getFilesDir().getAbsolutePath())
                             : decodePngRw(bytes);
            Log.i(LOG_TAG, "native result: " + result);
            publish(result);
        } catch (IOException error) {
            Log.w(LOG_TAG, "fixture rejected: " + error.getMessage());
            publish("REJECTED | " + error.getMessage());
        }
        stopSelf(startId);
        return START_NOT_STICKY;
    }
}
