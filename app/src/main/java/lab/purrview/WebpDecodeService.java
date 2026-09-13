package lab.purrview;

import android.content.Intent;
import android.util.Log;
import java.io.IOException;
import java.io.InputStream;

/**
 * The vulnerable decoder lives in a separate, non-sticky process. A decoder
 * crash cannot take down the visible PurrView activity. This service has no
 * exported entry point and accepts only bundled lab fixtures.
 */
public final class WebpDecodeService extends FixtureDecodeService {
    public static final String ACTION_START = "lab.purrview.action.WEBP_START";
    public static final String ACTION_RESULT = "lab.purrview.action.WEBP_RESULT";
    public static final String EXTRA_ASSET = "asset";
    private static final int MAX_INPUT = 256 * 1024;
    private static final String LOG_TAG = "PurrView/WebP";

    static {
        System.loadLibrary("purrview");
    }

    public WebpDecodeService() {
        super(ACTION_RESULT, MAX_INPUT);
    }

    private native String decodeWebp(byte[] input);

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || !ACTION_START.equals(intent.getAction())) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        String asset = intent.getStringExtra(EXTRA_ASSET);
        if (!"bad.webp".equals(asset) && !"meow.webp".equals(asset)) {
            publish("REJECTED | worker accepts only bundled WebP fixtures");
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        publish("WORKER STARTED | isolated decoder process | " + asset);
        Log.i(LOG_TAG, "worker started in :webp_decoder with fixture=" + asset);
        try (InputStream input = getAssets().open(asset)) {
            byte[] bytes = readBounded(input);
            Log.i(LOG_TAG, "fixture loaded: bytes=" + bytes.length + "; invoking native WebP decoder");
            // Mark the one-shot service finished before entering the decoder;
            // a native fault must not cause Android to redeliver the request.
            stopSelf(startId);
            // The native call is the only operation in this worker that touches
            // libwebp. No dynamic code loading or command execution follows it.
            String result = decodeWebp(bytes);
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
