package simpleperf.example.cpp;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

public class SleepActivity extends AppCompatActivity {

    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sleep);
        createSleepThreadFromJNI();
    }

    private native void createSleepThreadFromJNI();
}