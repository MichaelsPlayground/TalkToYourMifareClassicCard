package de.androidcrypto.talktoyourmifareclassiccard;

import static de.androidcrypto.talktoyourmifareclassiccard.Utils.setBitInByte;
import static de.androidcrypto.talktoyourmifareclassiccard.Utils.unsetBitInByte;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.textfield.TextInputLayout;

import java.io.IOException;
import java.util.Arrays;

public class AccessConditionsEncoderActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = AccessConditionsEncoderActivity.class.getName();

    /**
     * UI elements
     */

    private com.google.android.material.textfield.TextInputEditText output, encodedAccessConditions, applicationIdentifier, numberOfKeys, carAppKey;
    private com.google.android.material.textfield.TextInputLayout outputLayout;
    private CheckBox masterKeyIsChangable, masterKeyAuthenticationNeededDirListing, masterKeyAuthenticationNeededCreateDelete, masterKeySettingsChangeAllowed;
    private Button moreInformation, encodeAccessConditions;

    // radio buttons for sector trailer sets

    private RadioButton rbTrailerSet1, rbTrailerSet2, rbTrailerSet3, rbTrailerSet4, rbTrailerSet5, rbTrailerSet6, rbTrailerSet7, rbTrailerSet8;

    private RadioButton rbTrailerKeyAWriteNever, rbTrailerKeyAWriteKeyA, rbTrailerKeyAWriteKeyB;
    private RadioButton rbTrailerAccessBitsReadKeyA, rbTrailerAccessBitsReadKeyAB;
    private RadioButton rbTrailerAccessBitsWriteNever, rbTrailerAccessBitsWriteKeyA, rbTrailerAccessBitsWriteKeyB;
    private RadioButton rbTrailerKeyBReadNever, rbTrailerKeyBReadKeyA;
    private RadioButton rbTrailerKeyBWriteNever, rbTrailerKeyBWriteKeyA, rbTrailerKeyBWriteKeyB;

    private RadioButton rbDoNothing, rbChangeAppKeysToChanged, rbChangeAppKeysToDefault, rbChangeMasterAppKeyToChanged, rbChangeMasterAppKeyToDefault;

    /**
     * general constants
     */

    private final int COLOR_GREEN = Color.rgb(0, 255, 0);
    private final int COLOR_RED = Color.rgb(255, 0, 0);
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};

    /**
     * NFC handling
     */

    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;


    private byte[] errorCode;
    private String errorCodeReason = "";
    private boolean isDesfireEv3 = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_access_condition_encoder);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etCreateApplicationOutput);
        outputLayout = findViewById(R.id.etCreateApplicationOutputLayout);
        moreInformation = findViewById(R.id.btnCreateApplicationMoreInformation);

        // radio button for trailer sector
        rbTrailerSet1 = findViewById(R.id.rbACEncoderTrailerSet1);
        rbTrailerSet2 = findViewById(R.id.rbACEncoderTrailerSet2);
        rbTrailerSet3 = findViewById(R.id.rbACEncoderTrailerSet3);
        rbTrailerSet4 = findViewById(R.id.rbACEncoderTrailerSet4);
        rbTrailerSet5 = findViewById(R.id.rbACEncoderTrailerSet5);
        rbTrailerSet6 = findViewById(R.id.rbACEncoderTrailerSet6);
        rbTrailerSet7 = findViewById(R.id.rbACEncoderTrailerSet7);
        rbTrailerSet8 = findViewById(R.id.rbACEncoderTrailerSet8);


        /*
        rbTrailerKeyAWriteNever = findViewById(R.id.rbACEncoderTrailerKeyAWriteNever);
        rbTrailerKeyAWriteKeyA = findViewById(R.id.rbACEncoderTrailerKeyAWriteKeyA);
        rbTrailerKeyAWriteKeyB = findViewById(R.id.rbACEncoderTrailerKeyAWriteKeyB);
        rbTrailerAccessBitsReadKeyA = findViewById(R.id.rbACEncoderTrailerAccessBitsReadKeyA);
        rbTrailerAccessBitsReadKeyAB = findViewById(R.id.rbACEncoderTrailerAccessBitsReadKeyAB);
        rbTrailerAccessBitsWriteNever = findViewById(R.id.rbACEncoderTrailerAccessBitsWriteNever);
        rbTrailerAccessBitsWriteKeyA = findViewById(R.id.rbACEncoderTrailerAccessBitsWriteKeyA);
        rbTrailerAccessBitsWriteKeyB = findViewById(R.id.rbACEncoderTrailerAccessBitsWriteKeyB);
        rbTrailerKeyBReadNever = findViewById(R.id.rbACEncoderTrailerKeyBReadNever);
        rbTrailerKeyBReadKeyA = findViewById(R.id.rbACEncoderTrailerKeyBReadKeyA);
        rbTrailerKeyBWriteNever = findViewById(R.id.rbACEncoderTrailerKeyBWriteNever);
        rbTrailerKeyBWriteKeyA = findViewById(R.id.rbACEncoderTrailerKeyBWriteKeyA);
        rbTrailerKeyBWriteKeyB = findViewById(R.id.rbACEncoderTrailerKeyBWriteKeyB);
        encodeAccessConditions = findViewById(R.id.btnACEncoderEncode);
        encodedAccessConditions = findViewById(R.id.etACEncoderEncoded);
*/



        applicationIdentifier = findViewById(R.id.etCreateApplicationAid);
        numberOfKeys = findViewById(R.id.etCreateApplicationNumberOfKeys);
        carAppKey = findViewById(R.id.etCreateApplicationCarKeyNumber);
 /*       masterKeyIsChangable = findViewById(R.id.cbCreateApplicationBit0MasterKeyIsChangeable);
        masterKeyAuthenticationNeededDirListing = findViewById(R.id.cbCreateApplicationBit1MasterKeyAuthenticationNeededDirListing);
        masterKeyAuthenticationNeededCreateDelete = findViewById(R.id.cbCreateApplicationBit2MasterKeyAuthenticationNeededCreateDelete);
        masterKeySettingsChangeAllowed = findViewById(R.id.cbCreateApplicationBit3MasterKeySettingsChangeAllowed);
*/
        checkboxesToDefault();

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        moreInformation.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // provide more information about the application and file
                showDialog(AccessConditionsEncoderActivity.this, getResources().getString(R.string.more_information_access_conditions_encoder));
            }
        });

        encodeAccessConditions.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.d(TAG, "encodeAccessConditions started");

                byte[] enc = new byte[4];
                boolean isSet1 = rbTrailerSet1.isChecked();
                boolean isSet2 = rbTrailerSet2.isChecked();
                boolean isSet3 = rbTrailerSet3.isChecked();
                boolean isSet4 = rbTrailerSet4.isChecked();
                boolean isSet5 = rbTrailerSet5.isChecked();
                boolean isSet6 = rbTrailerSet6.isChecked();
                boolean isSet7 = rbTrailerSet7.isChecked();
                boolean isSet8 = rbTrailerSet8.isChecked();
                byte enc6 = 0, enc7 = 0, enc8 = 0;
                if (isSet1) {
                    // c1 3 = 0, c2 3 = 0, c3 3 = 0
                    enc6 = unsetBitInByte(enc6, 3);
                    enc7 = setBitInByte(enc7, 7);
                    enc6 = unsetBitInByte(enc6, 7);
                    enc8 = setBitInByte(enc8, 3);
                    enc7 = unsetBitInByte(enc7, 3);
                    enc8 = setBitInByte(enc8, 7);
                }
                if (isSet2) {
                    // c1 3 = 0, c2 3 = 1, c3 3 = 0
                    enc6 = unsetBitInByte(enc6, 3);
                    enc7 = setBitInByte(enc7, 7);
                    enc6 = unsetBitInByte(enc6, 7);
                    enc8 = setBitInByte(enc8, 3);
                    enc7 = unsetBitInByte(enc7, 3);
                    enc8 = setBitInByte(enc8, 7);
                }



                if (rbTrailerKeyAWriteNever.isChecked()) {

                }




                encodedAccessConditions.setText(Utils.bytesToHexNpe(enc));

            }
        });
    }

    private void runCreateApplication() {
        clearOutputFields();
        String logString = "runCreateApplication";
        writeToUiAppend(output, logString);

        // sanity checks
        String appId = applicationIdentifier.getText().toString();
        if (TextUtils.isEmpty(appId)) {
        }
        byte[] appIdBytes = Utils.hexStringToByteArray(appId);
        if (applicationIdentifier == null) {
            writeToUiAppendBorderColor(output, outputLayout, "please enter a 6 hex characters long application identifier", COLOR_RED);
            return;
        }
        //Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB = change the order
        if (appIdBytes.length != 3) {
            writeToUiAppendBorderColor(output, outputLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
            return;
        }
        String numKeys = numberOfKeys.getText().toString();
        if (TextUtils.isEmpty(numKeys)) {
            writeToUiAppendBorderColor(output, outputLayout, "please enter the number of keys in range 1..14", COLOR_RED);
            return;
        }
        int numberOfApplicationKeys = Integer.parseInt(numKeys);
        if ((numberOfApplicationKeys < 1) || (numberOfApplicationKeys > 14)) {
            writeToUiAppendBorderColor(output, outputLayout, "please enter the number of keys in range 1..14", COLOR_RED);
            return;
        }
        // no sanity check on this as it is fixed
        String carKeyNumber = carAppKey.getText().toString();
        byte carKeyByte = Byte.parseByte(carKeyNumber);
        int carKeyInt = Integer.parseInt(carKeyNumber);

        // now the funny part - the application settings - bitwise combined with carKeyByte
        /*
			bit 0 is most right bit (counted from right to left)
			bit 0 = application master key is changeable (1) or frozen (0)
			bit 1 = application master key authentication is needed for file directory access (1)
			bit 2 = application master key authentication is needed before CreateFile / DeleteFile (1)
			bit 3 = change of the application master key settings is allowed (1)
			bit 4-7 = hold the Access Rights for changing application keys (ChangeKey command)
			• 0x0: Application master key authentication is necessary to change any key (default).
			• 0x1 .. 0xD: Authentication with the specified key is necessary to change any key.
			• 0xE: Authentication with the key to be changed (same KeyNo) is necessary to change a key.
			• 0xF: All Keys (except application master key, see Bit0) within this application are frozen.
		 */
        byte appSettings = (byte) 0x00;
        if (masterKeyIsChangable.isChecked()) {
            appSettings = setBitInByte(appSettings, 0);
        } else {
            appSettings = unsetBitInByte(appSettings, 0);
        }
        // attention - the set/unset are changed due to naming
        if (masterKeyAuthenticationNeededDirListing.isChecked()) {
            appSettings = unsetBitInByte(appSettings, 1);
        } else {
            appSettings = setBitInByte(appSettings, 1);
        }
        // attention - the set/unset are changed due to naming
        if (masterKeyAuthenticationNeededCreateDelete.isChecked()) {
            appSettings = unsetBitInByte(appSettings, 2);
        } else {
            appSettings = setBitInByte(appSettings, 2);
        }
        if (masterKeySettingsChangeAllowed.isChecked()) {
            appSettings = setBitInByte(appSettings, 3);
        } else {
            appSettings = unsetBitInByte(appSettings, 3);
        }
        // now we concatenate the Car Application Key with the App Settings
        char upperNibble = Utils.byteToUpperNibble(carKeyByte);
        char lowerNibble = Utils.byteToLowerNibble(appSettings);
        byte applicationMasterSettings = Utils.nibblesToByte(upperNibble, lowerNibble);

        boolean success;
        byte[] errorCode;
        String errorCodeReason = "";
        writeToUiAppend(output, "");
        String stepString = "1 select the Master Application";
        writeToUiAppend(output, stepString);
        success = true;
        errorCode = null;
        if (success) {
            writeToUiAppendBorderColor(stepString + " SUCCESS", COLOR_GREEN);
        } else {

        }

        stepString = "2 create the new application";
        writeToUiAppend(output, stepString);

        vibrateShort();
    }


    private void checkboxesToDefault() {
        /*
        masterKeyIsChangable.setChecked(true);
        masterKeyAuthenticationNeededDirListing.setChecked(false);
        masterKeyAuthenticationNeededCreateDelete.setChecked(false);
        masterKeySettingsChangeAllowed.setChecked(true);
        */
    }

    /**
     * section for NFC handling
     */

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {

        clearOutputFields();
        writeToUiAppend("NFC tag discovered");
        isoDep = null;
        try {
            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                // Make a Vibration
                vibrateShort();

                runOnUiThread(() -> {
                    output.setText("");
                    output.setBackgroundColor(getResources().getColor(R.color.white));
                });
                isoDep.connect();
                if (!isoDep.isConnected()) {
                    writeToUiAppendBorderColor("could not connect to the tag, aborted", COLOR_RED);
                    isoDep.close();
                    return;
                }


                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend("tag id: " + Utils.bytesToHex(tagIdByte));
                Log.d(TAG, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppendBorderColor("The app and DESFire EV3 tag are ready to use", COLOR_GREEN);

                runCreateApplication();

            }
        } catch (IOException e) {
            writeToUiAppendBorderColor("IOException: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        } catch (Exception e) {
            writeToUiAppendBorderColor("Exception: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }


    /**
     * section for UI elements
     */

    private void writeToUiAppend(String message) {
        writeToUiAppend(output, message);
    }

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    private void writeToUi(TextView textView, String message) {
        runOnUiThread(() -> {
            textView.setText(message);
        });
    }

    private void writeToUiAppendBorderColor(String message, int color) {
        writeToUiAppendBorderColor(output, outputLayout, message, color);
    }

    private void writeToUiAppendBorderColor(TextView textView, TextInputLayout textInputLayout, String message, int color) {
        runOnUiThread(() -> {

            // set the color to green
            //Color from rgb
            // int color = Color.rgb(255,0,0); // red
            //int color = Color.rgb(0,255,0); // green
            //Color from hex string
            //int color2 = Color.parseColor("#FF11AA"); light blue
            int[][] states = new int[][]{
                    new int[]{android.R.attr.state_focused}, // focused
                    new int[]{android.R.attr.state_hovered}, // hovered
                    new int[]{android.R.attr.state_enabled}, // enabled
                    new int[]{}  //
            };
            int[] colors = new int[]{
                    color,
                    color,
                    color,
                    //color2
                    color
            };
            ColorStateList myColorList = new ColorStateList(states, colors);
            textInputLayout.setBoxStrokeColorStateList(myColorList);

            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    public void showDialog(Activity activity, String msg) {
        final Dialog dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(true);
        dialog.setContentView(R.layout.logdata);
        TextView text = dialog.findViewById(R.id.tvLogData);
        //text.setMovementMethod(new ScrollingMovementMethod());
        text.setText(msg);
        Button dialogButton = dialog.findViewById(R.id.btnLogDataOk);
        dialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dialog.dismiss();
            }
        });
        dialog.show();
    }

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

    private void clearOutputFields() {
        runOnUiThread(() -> {
            output.setText("");
        });
        // reset the border color to primary for errorCode
        int color = R.color.colorPrimary;
        int[][] states = new int[][]{
                new int[]{android.R.attr.state_focused}, // focused
                new int[]{android.R.attr.state_hovered}, // hovered
                new int[]{android.R.attr.state_enabled}, // enabled
                new int[]{}  //
        };
        int[] colors = new int[]{
                color,
                color,
                color,
                color
        };
        ColorStateList myColorList = new ColorStateList(states, colors);
        outputLayout.setBoxStrokeColorStateList(myColorList);
    }

    private void vibrateShort() {
        // Make a Sound
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(50, 10));
        } else {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            v.vibrate(50);
        }
    }

    /**
     * section for options menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_return_home, menu);

        MenuItem mGoToHome = menu.findItem(R.id.action_return_main);
        mGoToHome.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(AccessConditionsEncoderActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

}