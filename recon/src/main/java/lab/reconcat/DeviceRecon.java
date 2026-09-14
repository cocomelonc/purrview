package lab.reconcat;

import android.os.Build;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Public, permission-free {@link Build} snapshot of the device ReconCat is
 * installed on - the attacker's own recon step in the PurrView demo, kept in
 * a separate app from the vulnerable target so the target is never asked to
 * fingerprint itself.
 *
 * <p>Deliberately excludes anything that acts as a persistent device
 * identifier (no {@code Build.SERIAL}, {@code ANDROID_ID}, IMEI) and
 * anything that is build-machine metadata rather than device identity (no
 * {@code Build.HOST}/{@code USER}/{@code FINGERPRINT}/radio version) - only
 * fields describing the hardware itself.
 */
final class DeviceRecon {
    private DeviceRecon() {
    }

    static String snapshotJson() {
        JSONObject info = new JSONObject();
        try {
            info.put("manufacturer", Build.MANUFACTURER);
            info.put("model", Build.MODEL);
            info.put("device", Build.DEVICE);
            info.put("brand", Build.BRAND);
            info.put("hardware", Build.HARDWARE);
            info.put("board", Build.BOARD);
            info.put("type", Build.TYPE);
            info.put("arch", Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "unknown");
            info.put("sdk", Build.VERSION.SDK_INT);
        } catch (JSONException ignored) {
            // JSONObject#put only throws for a null key; every key above is a literal.
        }
        return info.toString();
    }
}
