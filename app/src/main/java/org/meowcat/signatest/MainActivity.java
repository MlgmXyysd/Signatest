package org.meowcat.signatest;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

@SuppressLint({"StaticFieldLeak", "SetTextI18n"})
public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("native");
    }

    public static char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    public static final String SIGN = "04AEEB5B235923552BBC3B64ABC5FF9A9A14C7F8";
    public static final String TAG = "Signatest";
    public static MessageDigest messagedigest = null;
    public static Context context;
    public static PackageInfo packageInfo;
    public static ApplicationInfo applicationInfo;
    public static TextView tvCheck;
    public static TextView tvMD5;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        context = getApplicationContext();
        tvCheck = findViewById(R.id.local_check);
        tvMD5 = findViewById(R.id.network_md5);
        StringBuilder sb = new StringBuilder();
        try {
            packageInfo = context.getPackageManager().getPackageInfo(BuildConfig.APPLICATION_ID, 0);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        applicationInfo = context.getApplicationInfo();
        File packageResourcePath = new File(context.getPackageResourcePath());
        sb.append("packageResourcePath：").append(context.getPackageResourcePath()).append("\n");
        File packageSourceDirPath = new File(packageInfo.applicationInfo.sourceDir);
        sb.append("packageSourceDir：").append(packageInfo.applicationInfo.sourceDir).append("\n");
        File applicationSourceDirPath = new File(applicationInfo.sourceDir);
        sb.append("applicationSourceDir：").append(applicationInfo.sourceDir).append("\n");
        sb.append("预期签名值：" + SIGN + "\n");
        for (String signature : getSignaturePackageInfo()) {
            sb.append("java层签名: ").append(signature).append("\n");
            Log.i(TAG, "javaSignatureSha1: " + signature);
        }
        sb.append("JNI层结果：").append(checkSignature(context, SIGN)).append("\n");
        Log.i(TAG, "packageResourcePath: " + getSha1(packageResourcePath));
        sb.append("packageResourcePath：").append(getSha1(packageResourcePath)).append("\n");
        Log.i(TAG, "packageSourceDir: " + getSha1(packageSourceDirPath));
        sb.append("packageSourceDir：").append(getSha1(packageResourcePath)).append("\n");
        Log.i(TAG, "applicationSourceDir: " + getSha1(applicationSourceDirPath));
        sb.append("applicationSourceDir：").append(getSha1(packageResourcePath)).append("\n");
        tvCheck.setText(sb.toString());
        Thread thread = new Thread() {
            @Override
            public void run() {
                try {
                    URL url = new URL("https://cdn.meowcat.org/signatest.md5");
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setConnectTimeout(10000);
                    conn.setReadTimeout(10000);
                    if (conn.getResponseCode() == 200) {
                        InputStream is = conn.getInputStream();
                        StringBuilder sb = new StringBuilder();
                        String line;
                        BufferedReader br = new BufferedReader(new InputStreamReader(is));
                        while ((line = br.readLine()) != null) {
                            sb.append(line);
                        }
                        final String result = sb.toString();
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                updateMD5(true, result);
                            }
                        });
                    } else {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                updateMD5(false, "");
                            }
                        });
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            updateMD5(false, "");
                        }
                    });
                }
            }
        };
        thread.start();
    }

    public static void updateMD5(boolean success, String result) {
        if (success) {
            tvMD5.setText("网络MD5: " + result);
        } else {
            tvMD5.setText("网络MD5获取失败");
        }
    }

    // 获取文件的md5值，用于和网络端进行比对
    public static String getSha1(File file) {
        try {
            messagedigest = MessageDigest.getInstance("SHA-1");
            FileInputStream in = new FileInputStream(file);
            FileChannel ch = in.getChannel();
            MappedByteBuffer byteBuffer = ch.map(FileChannel.MapMode.READ_ONLY, 0,
                    file.length());
            messagedigest.update(byteBuffer);
            return bufferToHex(messagedigest.digest());
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return "获取失败";
    }

    // 使用packageInfo获取签名的SHA值
    @SuppressLint("PackageManagerGetSignatures")
    public String[] getSignaturePackageInfo() {
        ArrayList<String> result = new ArrayList<>();
        PackageInfo packageInfo;
        try {
            packageInfo = context.getPackageManager().getPackageInfo(BuildConfig.APPLICATION_ID, PackageManager.GET_SIGNATURES);
            for (Signature signature : packageInfo.signatures) {
                result.add(byte2Hex(MessageDigest.getInstance("SHA").digest(signature.toByteArray())));
            }
        } catch (NoSuchAlgorithmException | PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return result.toArray(new String[0]);
    }

    // 使用JNI方法获取签名的SHA值
    public native boolean checkSignature(Context context, String sha1);

    // 以下为工具方法
    private String byte2Hex(byte[] arr) {
        StringBuilder str = new StringBuilder(arr.length * 2);
        for (byte b : arr) {
            String h = Integer.toHexString(b);
            int l = h.length();
            if (l == 1) {
                h = "0" + h;
            }
            if (l > 2) {
                h = h.substring(l - 2, l);
            }
            str.append(h.toUpperCase());
        }
        return str.toString();
    }

    private static String bufferToHex(byte[] bytes) {
        return bufferToHex(bytes, 0, bytes.length);
    }

    @SuppressWarnings("SameParameterValue")
    private static String bufferToHex(byte[] bytes, int m, int n) {
        StringBuffer stringbuffer = new StringBuffer(2 * n);
        int k = m + n;
        for (int l = m; l < k; l++) {
            appendHexPair(bytes[l], stringbuffer);
        }
        return stringbuffer.toString();
    }

    private static void appendHexPair(byte bt, StringBuffer stringbuffer) {
        char c0 = hexDigits[(bt & 0xf0) >> 4];
        char c1 = hexDigits[bt & 0xf];
        stringbuffer.append(c0);
        stringbuffer.append(c1);
    }

}
