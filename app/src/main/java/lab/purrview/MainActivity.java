package lab.purrview;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.util.function.Supplier;

/** Small conference screen for the native decoder workers. */
public final class MainActivity extends Activity {
    private static final int PURPLE = 0xff7446ba;
    private static final int TEXT_DARK = 0xff292236;
    private static final int CARD_BG = 0xfff2ebfa;
    private static final int BUTTON_BG = 0xfffbf9fe;
    private static final int BUTTON_BORDER = 0xffd8c6ed;
    private static final long WORKER_TIMEOUT_MS = 4000;

    static {
        System.loadLibrary("purrview");
    }

    private final Handler timeout = new Handler();
    private TextView status;
    private TextView mcttpStatus;
    private Button calculator;
    private String activeWorker;

    private native String selfAslr();

    private final BroadcastReceiver workerReceiver = new BroadcastReceiver() {
        @Override public void onReceive(android.content.Context context, Intent intent) {
            String message = intent.getStringExtra("status");
            if (message == null || status == null) return;
            String source = intent.getAction();
            status.setText(message);
            if (SmsDecodeService.ACTION_RESULT.equals(source) && mcttpStatus != null) {
                mcttpStatus.setText(message);
            }
            if (message.startsWith("WORKER STARTED")) {
                activeWorker = source;
            } else if (source != null && source.equals(activeWorker)) {
                activeWorker = null;
                calculator.setEnabled(true);
            }
        }
    };

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private TextView label(LinearLayout parent, String value, int size) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(TEXT_DARK);
        view.setPadding(0, dp(6), 0, dp(6));
        parent.addView(view);
        return view;
    }

    private void card(TextView view) {
        GradientDrawable background = new GradientDrawable();
        background.setColor(CARD_BG);
        background.setCornerRadius(dp(12));
        view.setBackground(background);
        view.setPadding(dp(14), dp(12), dp(14), dp(12));
    }

    private Button button(LinearLayout parent, String value, View.OnClickListener action) {
        Button button = new Button(this);
        button.setText(value);
        button.setAllCaps(false);
        button.setTextColor(PURPLE);
        GradientDrawable background = new GradientDrawable();
        background.setColor(BUTTON_BG);
        background.setCornerRadius(dp(14));
        background.setStroke(dp(1), BUTTON_BORDER);
        button.setBackground(background);
        button.setStateListAnimator(null);
        button.setOnClickListener(action);
        parent.addView(button, new LinearLayout.LayoutParams(0, dp(52), 1));
        return button;
    }

    private LinearLayout buttonRow(LinearLayout parent) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER);
        parent.addView(row, new LinearLayout.LayoutParams(-1, dp(58)));
        return row;
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(PURPLE);

        LinearLayout page = buildPage();

        buildHero(page);
        buildIntro(page);
        buildMcttpSection(page);
        buildPngSection(page);
        buildWebpSection(page);
        buildJpegSection(page);
        buildFooter(page);

        registerWorkerReceiver();
    }

    /** Creates the scrollable page container and installs it as the content view. */
    private LinearLayout buildPage() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.WHITE);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(20), dp(22), dp(20), dp(28));
        scroll.addView(page);
        setContentView(scroll);
        return page;
    }

    /** Cat avatar, app name and tagline at the top of the page. */
    private void buildHero(LinearLayout page) {
        LinearLayout hero = new LinearLayout(this);
        hero.setOrientation(LinearLayout.VERTICAL);
        hero.setGravity(Gravity.CENTER_HORIZONTAL);
        page.addView(hero, new LinearLayout.LayoutParams(-1, dp(308)));
        ImageView cat = new ImageView(this);
        cat.setImageResource(R.drawable.cat);
        cat.setContentDescription("PurrView cat");
        cat.setScaleType(ImageView.ScaleType.CENTER_CROP);
        GradientDrawable catBackground = new GradientDrawable();
        catBackground.setShape(GradientDrawable.OVAL);
        catBackground.setColor(Color.BLACK);
        cat.setBackground(catBackground);
        cat.setClipToOutline(true);
        hero.addView(cat, new LinearLayout.LayoutParams(dp(176), dp(176)));
        TextView name = label(hero, "PurrView", 34);
        name.setTextColor(PURPLE);
        name.setTypeface(null, Typeface.BOLD);
        name.setGravity(Gravity.CENTER);
        TextView tagline = label(hero, "small image · real native code", 13);
        tagline.setGravity(Gravity.CENTER);
    }

    /** Short explanation card shown above the demo sections. */
    private void buildIntro(LinearLayout page) {
        TextView intro = label(page,
                "A minimal memory-safety demo. Each decoder runs in its own process; the UI stays visible for logcat evidence.", 14);
        card(intro);
    }

    /** MCTTP 2026 talk section: ASLR self-check and SMS PDU PoC. */
    private void buildMcttpSection(LinearLayout page) {
        label(page, "MCTTP 2026 demo", 18);
        LinearLayout mcttpButtons = buttonRow(page);
        button(mcttpButtons, "ASLR self-check", v -> runAslrSelfCheck());
        button(mcttpButtons, "SMS PDU PoC", v -> runSmsPduPoc());
        mcttpStatus = label(page, "Educational and research purposes.", 13);
        mcttpStatus.setTypeface(Typeface.MONOSPACE);
        card(mcttpStatus);
    }

    /** PNG · PurrView parser section. */
    private void buildPngSection(LinearLayout page) {
        label(page, "PNG · PurrView parser", 18);
        LinearLayout pngButtons = buttonRow(page);
        button(pngButtons, "Run fixed", v -> startPngWorker(true));
        button(pngButtons, "Run PoC", v -> startPngWorker(false));
        button(pngButtons, "Run AI PoC", v -> startAiPngWorker());
        LinearLayout pngRwButtons = buttonRow(page);
        button(pngRwButtons, "R/W PoC (memory)", v -> startRwPngWorker("memory"));
        button(pngRwButtons, "R/W PoC (file)", v -> startRwPngWorker("file"));
    }

    /** WebP · libwebp 1.3.1 section. */
    private void buildWebpSection(LinearLayout page) {
        label(page, "WebP · libwebp 1.3.1", 18);
        LinearLayout webpButtons = buttonRow(page);
        button(webpButtons, "Run control", v -> startWorker(WebpDecodeService.class,
                WebpDecodeService.ACTION_START, "meow.webp", "WebP"));
        button(webpButtons, "Run PoC", v -> startWorker(WebpDecodeService.class,
                WebpDecodeService.ACTION_START, "bad.webp", "WebP"));
    }

    /** JPEG PPM · libjpeg-turbo 2.0.4 section. */
    private void buildJpegSection(LinearLayout page) {
        label(page, "JPEG PPM · libjpeg-turbo 2.0.4", 18);
        LinearLayout jpegButtons = buttonRow(page);
        button(jpegButtons, "Run control", v -> startWorker(JpegDecodeService.class,
                JpegDecodeService.ACTION_START, "normal.pgm", "JPEG"));
        button(jpegButtons, "Run PoC", v -> startWorker(JpegDecodeService.class,
                JpegDecodeService.ACTION_START, "poc.pgm", "JPEG"));
    }

    /** Status line, explicit calculator action and closing disclaimer. */
    private void buildFooter(LinearLayout page) {
        status = label(page, "Ready. Start a worker, then watch adb logcat.", 13);
        status.setTypeface(Typeface.MONOSPACE);
        card(status);
        calculator = new Button(this);
        calculator.setText("Open calculator (explicit demo action)");
        calculator.setAllCaps(false);
        calculator.setTextColor(PURPLE);
        GradientDrawable calculatorBackground = new GradientDrawable();
        calculatorBackground.setColor(PURPLE);
        calculatorBackground.setCornerRadius(dp(14));
        calculator.setBackground(calculatorBackground);
        calculator.setTextColor(Color.WHITE);
        calculator.setStateListAnimator(null);
        calculator.setEnabled(false);
        calculator.setOnClickListener(v -> openCalculator());
        page.addView(calculator, new LinearLayout.LayoutParams(-1, dp(56)));
        TextView note = label(page, "Educational and research purposes.", 12);
        note.setGravity(Gravity.CENTER);
    }

    /** Subscribes to result broadcasts from every decoder worker. */
    private void registerWorkerReceiver() {
        IntentFilter filter = new IntentFilter();
        filter.addAction(PngDecodeService.ACTION_RESULT);
        filter.addAction(WebpDecodeService.ACTION_RESULT);
        filter.addAction(JpegDecodeService.ACTION_RESULT);
        filter.addAction(SmsDecodeService.ACTION_RESULT);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(workerReceiver, filter, RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(workerReceiver, filter);
        }
    }

    private void startPngWorker(boolean fixed) {
        startPngWorker(fixed, "purrview-oob.png", null);
    }

    private void startAiPngWorker() {
        startPngWorker(false, null, "purrview-ai.png");
    }

    private void startPngWorker(boolean fixed, String asset, String privateFile) {
        String mode = fixed ? "fixed" : privateFile != null ? "AI PoC" : "PoC";
        launchWorker(PngDecodeService.ACTION_RESULT, "STARTING | PNG parser | " + mode, () -> {
            Intent request = new Intent(this, PngDecodeService.class)
                    .setAction(PngDecodeService.ACTION_START)
                    .putExtra(PngDecodeService.EXTRA_FIXED, fixed);
            if (asset != null) request.putExtra(PngDecodeService.EXTRA_ASSET, asset);
            if (privateFile != null) request.putExtra(PngDecodeService.EXTRA_PRIVATE_FILE, privateFile);
            return request;
        });
    }

    private void startRwPngWorker(String target) {
        launchWorker(PngDecodeService.ACTION_RESULT, "STARTING | PNG parser | R/W PoC (" + target + ")", () ->
                new Intent(this, PngDecodeService.class)
                        .setAction(PngDecodeService.ACTION_START)
                        .putExtra(PngDecodeService.EXTRA_RW, true)
                        .putExtra(PngDecodeService.EXTRA_RW_TARGET, target)
                        .putExtra(PngDecodeService.EXTRA_PRIVATE_FILE, "purrview-rw.png"));
    }

    private void startWorker(Class<?> service, String action, String asset, String name) {
        String resultAction = action.replace("_START", "_RESULT");
        launchWorker(resultAction, "STARTING | " + name + " worker | " + asset,
                () -> new Intent(this, service).setAction(action).putExtra("asset", asset));
    }

    /**
     * Shared start/timeout/failure handling for every worker button. The request
     * is built inside the try so a failure while constructing it is reported the
     * same way as a failure from {@link #startService}.
     */
    private void launchWorker(String resultAction, String startingStatus, Supplier<Intent> request) {
        activeWorker = resultAction;
        calculator.setEnabled(false);
        status.setText(startingStatus);
        try {
            startService(request.get());
        } catch (RuntimeException error) {
            activeWorker = null;
            status.setText("WORKER START FAILED | " + error.getClass().getSimpleName());
            calculator.setEnabled(true);
            return;
        }
        timeout.postDelayed(() -> {
            if (activeWorker != null) {
                activeWorker = null;
                status.setText("WORKER EXITED WITHOUT RESULT | inspect adb logcat");
                calculator.setEnabled(true);
            }
        }, WORKER_TIMEOUT_MS);
    }

    private void openCalculator() {
        Intent intent = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_APP_CALCULATOR);
        try {
            startActivity(intent);
        } catch (android.content.ActivityNotFoundException error) {
            Toast.makeText(this, "No calculator app is installed.", Toast.LENGTH_SHORT).show();
        }
    }

    private void runAslrSelfCheck() {
        try {
            mcttpStatus.setText(selfAslr());
        } catch (UnsatisfiedLinkError error) {
            mcttpStatus.setText("ASLR SELF | module lookup unavailable");
        }
    }

    private void runSmsPduPoc() {
        mcttpStatus.setText("SMS PDU | EDUCATIONAL AND RESEARCH PURPOSES\n" +
                "local fixture → PurrView parser worker → logcat evidence");
        startSmsWorker();
    }

    private void startSmsWorker() {
        launchWorker(SmsDecodeService.ACTION_RESULT, "STARTING | local PDU parser | PoC",
                () -> new Intent(this, SmsDecodeService.class).setAction(SmsDecodeService.ACTION_START));
    }

    @Override protected void onDestroy() {
        timeout.removeCallbacksAndMessages(null);
        try {
            unregisterReceiver(workerReceiver);
        } catch (IllegalArgumentException ignored) {
        }
        super.onDestroy();
    }
}
