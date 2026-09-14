package lab.reconcat;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Minimal attacker-side recon tool for the PurrView demo: dumps this
 * device's own public Build.* fields (see DeviceRecon) on screen and to
 * logcat, where tools/ai_mutate.py can read it as a live --profile.
 */
public final class ReconActivity extends Activity {
    private static final String LOG_TAG = "ReconCat";

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);

        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setGravity(Gravity.CENTER_HORIZONTAL);
        page.setPadding(24, 60, 24, 24);

        int catSize = (int) (140 * getResources().getDisplayMetrics().density + 0.5f);
        ImageView cat = new ImageView(this);
        cat.setImageResource(R.drawable.cat);
        cat.setContentDescription("ReconCat");
        cat.setScaleType(ImageView.ScaleType.CENTER_CROP);
        GradientDrawable catBackground = new GradientDrawable();
        catBackground.setShape(GradientDrawable.OVAL);
        catBackground.setColor(Color.BLACK);
        cat.setBackground(catBackground);
        cat.setClipToOutline(true);
        page.addView(cat, new LinearLayout.LayoutParams(catSize, catSize));

        TextView title = new TextView(this);
        title.setText("ReconCat");
        title.setTextSize(24);
        page.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("attacker-side device recon for the PurrView demo");
        subtitle.setPadding(0, 8, 0, 24);
        page.addView(subtitle);

        TextView output = new TextView(this);
        output.setPadding(0, 0, 0, 24);
        page.addView(output);

        Button dump = new Button(this);
        dump.setText("Dump recon");
        dump.setOnClickListener(v -> {
            String snapshot = DeviceRecon.snapshotJson();
            output.setText(snapshot);
            Log.i(LOG_TAG, "RECON " + snapshot);
        });
        page.addView(dump);

        setContentView(page);
    }
}
