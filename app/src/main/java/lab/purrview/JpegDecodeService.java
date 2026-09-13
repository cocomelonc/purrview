package lab.purrview;

import android.content.Intent;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Runs the old libjpeg-turbo PPM reader in its own process. The service only
 * accepts the two checked-in fixtures and writes a private, short-lived file
 * so the native cjpeg reader can use its FILE*-based API.
 */
public final class JpegDecodeService extends FixtureDecodeService {
    public static final String ACTION_START = "lab.purrview.action.JPEG_START";
    public static final String ACTION_RESULT = "lab.purrview.action.JPEG_RESULT";
    public static final String EXTRA_ASSET = "asset";
    private static final int MAX_INPUT = 256 * 1024;
    private static final String LOG_TAG = "PurrView/JPEG";

    static {
        System.loadLibrary("purrview");
    }

    public JpegDecodeService() {
        super(ACTION_RESULT, MAX_INPUT);
    }

    private native String decodePpmPath(String path);

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || !ACTION_START.equals(intent.getAction())) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        String asset = intent.getStringExtra(EXTRA_ASSET);
        if (!"poc.pgm".equals(asset) && !"normal.pgm".equals(asset)) {
            publish("REJECTED | worker accepts only bundled PGM fixtures");
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        publish("WORKER STARTED | isolated decoder process | " + asset);
        Log.i(LOG_TAG, "worker started in :jpeg_decoder with fixture=" + asset);
        File fixture = null;
        try (InputStream input = getAssets().open(asset)) {
            byte[] bytes = readBounded(input);
            Log.i(LOG_TAG, "fixture loaded: bytes=" + bytes.length + "; invoking native PPM reader");
            fixture = File.createTempFile("purrview-", ".pgm", getCacheDir());
            try (FileOutputStream output = new FileOutputStream(fixture)) {
                output.write(bytes);
            }
            // Mark the one-shot service finished before entering the decoder;
            // a native fault must not cause Android to redeliver the request.
            stopSelf(startId);
            // This is the only native call. No shell, sockets, dynamic module
            // loading, or post-decoder action is connected to the result.
            String result = decodePpmPath(fixture.getAbsolutePath());
            Log.i(LOG_TAG, "native result: " + result);
            publish(result);
        } catch (IOException error) {
            Log.w(LOG_TAG, "fixture rejected: " + error.getMessage());
            publish("REJECTED | " + error.getMessage());
        } finally {
            if (fixture != null && fixture.exists() && !fixture.delete()) {
                fixture.deleteOnExit();
            }
        }
        stopSelf(startId);
        return START_NOT_STICKY;
    }
}
