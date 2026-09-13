package lab.purrview;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Shared plumbing for the bundled-fixture decoder workers: a bounded read of
 * the input stream and a result broadcast back to the visible activity. Each
 * subclass runs in its own manifest-declared process and owns its native
 * decode call; this base class touches neither.
 */
abstract class FixtureDecodeService extends Service {
    public static final String EXTRA_STATUS = "status";

    private final String resultAction;
    private final int maxInputBytes;

    protected FixtureDecodeService(String resultAction, int maxInputBytes) {
        this.resultAction = resultAction;
        this.maxInputBytes = maxInputBytes;
    }

    protected byte[] readBounded(InputStream input) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = input.read(chunk)) != -1) {
            if (result.size() + read > maxInputBytes) {
                throw new IOException("fixture exceeds " + (maxInputBytes / 1024) + " KiB");
            }
            result.write(chunk, 0, read);
        }
        return result.toByteArray();
    }

    protected void publish(String message) {
        sendBroadcast(new Intent(resultAction).setPackage(getPackageName())
                .putExtra(EXTRA_STATUS, message));
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}
