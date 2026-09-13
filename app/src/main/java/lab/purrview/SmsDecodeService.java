package lab.purrview;

import android.content.Intent;
import android.util.Log;
import java.io.IOException;
import java.io.InputStream;

/** PurrView-owned local PDU worker; it never opens the Android SMS provider. */
public final class SmsDecodeService extends FixtureDecodeService {
    public static final String ACTION_START = "lab.purrview.action.SMS_START";
    public static final String ACTION_RESULT = "lab.purrview.action.SMS_RESULT";
    private static final String FIXTURE = "purrview-pdu.bin";
    private static final int MAX_INPUT = 128 * 1024;
    private static final String LOG_TAG = "PurrView/SMS";

    static {
        System.loadLibrary("purrview");
    }

    public SmsDecodeService() {
        super(ACTION_RESULT, MAX_INPUT);
    }

    private native String decodePdu(byte[] input, boolean fixed);

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || !ACTION_START.equals(intent.getAction())) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        publish("WORKER STARTED | local PDU parser | PoC");
        Log.i(LOG_TAG, "worker started in :sms_decoder fixture=" + FIXTURE);
        try (InputStream input = getAssets().open(FIXTURE)) {
            byte[] bytes = readBounded(input);
            Log.i(LOG_TAG, "fixture loaded: bytes=" + bytes.length + "; invoking PurrView PDU parser");
            // Mark the one-shot service finished before entering the PoC. If the
            // native worker aborts, Android will not redeliver this start request.
            stopSelf(startId);
            String result = decodePdu(bytes, false);
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
