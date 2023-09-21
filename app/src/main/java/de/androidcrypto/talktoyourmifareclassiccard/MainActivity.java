package de.androidcrypto.talktoyourmifareclassiccard;

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
import android.nfc.tech.MifareClassic;
import android.nfc.tech.NfcA;
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
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.textfield.TextInputLayout;

import java.io.IOException;
import java.util.List;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback  {

    private static final String TAG = MainActivity.class.getName();
    private static final String OUTPUT_SEPARATOR_DOUBLE = "==========================";
    private static final String OUTPUT_SEPARATOR_SINGLE = "--------------------------";
    /**
     * UI elements
     */

    private com.google.android.material.textfield.TextInputEditText output;
    private TextInputLayout outputLayout;
    private Button moreInformation;

    private Button readCompleteTag;
    private com.google.android.material.textfield.TextInputEditText sectorsReadable;

    private com.shawnlin.numberpicker.NumberPicker npSectorIndex;
    private com.google.android.material.textfield.TextInputEditText manualAccessKey;
    private Button readSectorManual;


    private com.shawnlin.numberpicker.NumberPicker npBlockIndex;
    private Button readBlock;
    private com.google.android.material.textfield.TextInputEditText readBlockData;

    /**
     * general constants
     */

    private final int COLOR_GREEN = Color.rgb(0, 255, 0);
    private final int COLOR_RED = Color.rgb(255, 0, 0);


    /**
     * NFC handling
     */

    private NfcAdapter mNfcAdapter;
    //private NfcA nfcA;
    private MifareClassic mfc;
    private MifareClassicTagDetails mfcTagDetails;
    private Classic classic;
    private SectorMcModel[] sectorMcs;
    private byte[][] authKeyMatrix;
    private String[] authKeyTypeMatrix;
    private IsoDep isoDep;
    private byte[] tagIdByte;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etMainOutput);
        outputLayout = findViewById(R.id.etMainOutputLayout);
        moreInformation = findViewById(R.id.btnMainMoreInformation);

        readCompleteTag = findViewById(R.id.btnMainReadCompleteTag);
        sectorsReadable = findViewById(R.id.etMainSectorsReadable);

        npSectorIndex = findViewById(R.id.npSectorIndex);
        manualAccessKey = findViewById(R.id.etMainManualAccessKey);
        readSectorManual = findViewById(R.id.btnMainReadSectorManual);

        npBlockIndex = findViewById(R.id.npBlockIndex);
        readBlock = findViewById(R.id.btnMainReadBlock);
        readBlockData = findViewById(R.id.etMainReadBlock);

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        AccessConditions.context = getApplicationContext();

        moreInformation.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // provide more information about the application and file
                showDialog(MainActivity.this, getResources().getString(R.string.more_information_main));
            }
        });

        readCompleteTag.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will read the complete tag using default keys
                writeToUiAppendBorderColor("", Color.GRAY);
                sectorsReadable.setText("");
                writeToUiAppend("read the complete tag with default keys");

                if (mfcTagDetails == null) {
                    writeToUiAppendBorderColor("tap a Mifare Classic tag before reading, aborted", COLOR_RED);
                    return;
                }
                int sectorCount = mfcTagDetails.getSectorCount();
                writeToUiAppend("this tag has " + sectorCount + " sectors to read");
                sectorMcs = new SectorMcModel[sectorCount];

                // brute force method to check for known default authentication keys
                int numberOfSuccessAuths = classic.checkDefaultAuthentication();
                writeToUiAppend("number of successful authentications: " + numberOfSuccessAuths);
                authKeyMatrix = classic.getAuthenticationKeyMatrix();
                authKeyTypeMatrix = classic.getAuthenticationKeyTypeMatrix();
                for (int i = 0; i < sectorCount; i++) {
                    writeToUiAppend("sector: " + String.format("%02d", i) + ":" + Utils.bytesToHexNpe(authKeyMatrix[i]));
                }
                writeToUiAppend("Note: NULL means no default key found");
                String sectorsReadableString = "";
                for (int sectorIndex = 0; sectorIndex < sectorCount; sectorIndex++) {
                    writeToUiAppend("");
                    writeToUiAppend(OUTPUT_SEPARATOR_DOUBLE);
                    writeToUiAppend("reading sector " + sectorIndex);
                    writeToUiAppend("authKeyTypeMatrix " + authKeyTypeMatrix[sectorIndex]);
                    if ((authKeyTypeMatrix[sectorIndex] != null) && (!authKeyTypeMatrix[sectorIndex].equals(""))) {
                        byte[] sectorRead = classic.readSector(sectorIndex, authKeyMatrix[sectorIndex], authKeyTypeMatrix[sectorIndex]);
                        writeToUiAppend("keyType: " + authKeyTypeMatrix[sectorIndex]);
                        writeToUiAppend("sector: " + Utils.printData("data", sectorRead));
                        writeToUiAppend("errorCode: " + classic.getErrorCode() + " " + classic.getErrorCodeReason());
                        // public SectorMcModel(int sectorNumber, byte[] sectorRead, String keyType, byte[] key) {
                        SectorMcModel sectorMc = new SectorMcModel(sectorIndex, sectorRead, authKeyTypeMatrix[0], authKeyMatrix[0]);
                        if (sectorMc.isDataIsValid()) {
                            writeToUiAppend(sectorMc.dump());
                            sectorsReadableString += String.format("%02d ", sectorIndex);
                            sectorMcs[sectorIndex] = sectorMc;
                        }
                    }
                }
                sectorsReadable.setText(sectorsReadableString.trim());
                writeToUiAppendBorderColor("read complete tag success", COLOR_GREEN);
                vibrateShort();
            }
        });

        readSectorManual.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this will read the selected sector from tag using provided key
                writeToUiAppendBorderColor("", Color.GRAY);
                sectorsReadable.setText("");
                writeToUiAppend("read the selected sector from tag using the provided key");
                if (mfcTagDetails == null) {
                    writeToUiAppendBorderColor("tap a Mifare Classic tag before reading, aborted", COLOR_RED);
                    return;
                }
                int sectorIndex = npSectorIndex.getValue();
                String accessKeyString = manualAccessKey.getText().toString();
                if (!Utils.isHex(accessKeyString)) {
                    writeToUiAppendBorderColor("The entered access key is not a hex string or not of length 12, aborted", COLOR_RED);
                    return;
                }
                byte[] authKey = Utils.hexStringToByteArray(accessKeyString);
                String authKeyType = classic.authenticateSectorWithKey(sectorIndex, authKey);
                if (authKeyType.equals("")) {
                    // no success
                    writeToUiAppendBorderColor("Can not read the sector with the entered access key, aborted", COLOR_RED);
                    return;
                }
                // authentication is correct, try to read the sector
                byte[] sectorRead = classic.readSector(sectorIndex, authKey, authKeyType);
                writeToUiAppend("keyType: " + authKeyType);
                writeToUiAppend("sector: " + Utils.printData("data", sectorRead));
                writeToUiAppend("errorCode: " + classic.getErrorCode() + " " + classic.getErrorCodeReason());
                // appending the authKey and sectorData to the cached data
                SectorMcModel sectorMc = new SectorMcModel(sectorIndex, sectorRead, authKeyType, authKey);
                String sectorsReadableString = sectorsReadable.getText().toString();
                if (sectorMc.isDataIsValid()) {
                    writeToUiAppend(sectorMc.dump());
                    sectorsReadableString += String.format(" %02d ", sectorIndex);
                    sectorMcs[sectorIndex] = sectorMc;
                    authKeyMatrix[sectorIndex] = authKey;
                    authKeyTypeMatrix[sectorIndex] = authKeyType;
                }
                sectorsReadable.setText(sectorsReadableString.trim());
                writeToUiAppendBorderColor("read sector from tag success", COLOR_GREEN);
                vibrateShort();
            }
        });



        readBlock.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // read only if access key was found
                int selectedSector = npSectorIndex.getValue();
                int selectedBlock = npBlockIndex.getValue();
                int numberOfSuccessAuths = classic.checkDefaultAuthentication();
                if (numberOfSuccessAuths == 0) {
                    writeToUiAppend("no default key found, aborted");
                    return;
                }
                byte[] sectorAccessKey = classic.getAuthenticationKeyMatrix()[selectedSector];
                if (sectorAccessKey == null) {
                    writeToUiAppend("no access key found for selected sector, aborted");
                    return;
                }
                if (selectedSector == 0) {
                    if (selectedBlock == 0) {
                        writeToUiAppend("On sector 0 there are data blocks 1 + 2 only, aborted");
                        return;
                    }
                    // correct the selectedBlock by -1 as there are 2 data blocks only
                    selectedBlock = selectedBlock - 1;
                }
                String sectorAccessKeyType = classic.getAuthenticationKeyTypeMatrix()[selectedSector];
                // authenticate with the sectorAccessKey and type
                boolean success = classic.authenticateSectorWithKey(selectedSector, sectorAccessKey, sectorAccessKeyType);
                if (!success) {
                    writeToUiAppend("could not authenticate with access key, aborted");
                    return;
                }
                byte[] sectorRead = classic.readSector(selectedSector, sectorAccessKey, sectorAccessKeyType);
                if (sectorRead == null) {
                    writeToUiAppend("could not read the sector, aborted");
                    return;
                }
                SectorMcModel sectorMc = new SectorMcModel(selectedSector, sectorRead, sectorAccessKeyType, sectorAccessKey);
                if (sectorMc.isDataIsValid()) {
                    writeToUiAppend(sectorMc.dump());
                    List<byte[]> dataBlockList = sectorMc.getDataBlockList();
                    byte[] dataBlock = dataBlockList.get(selectedBlock);
                    readBlockData.setText(Utils.bytesToHexNpe(dataBlock));
                }
            }
        });
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
        mfc = null;
        try {
            mfc = MifareClassic.get(tag);
            if (mfc != null) {
                // Make a Vibration
                vibrateShort();

                runOnUiThread(() -> {
                    output.setText("");
                    output.setBackgroundColor(getResources().getColor(R.color.white));
                });
                mfc.connect();
                if (!mfc.isConnected()) {
                    writeToUiAppendBorderColor("could not connect to the tag, aborted", COLOR_RED);
                    mfc.close();
                    return;
                }
                writeToUiAppendBorderColor("The app and Mifare Classic tag are ready to use", COLOR_GREEN);
                // get tag details
                mfcTagDetails = new MifareClassicTagDetails(mfc);
                writeToUiAppend("Details: \n" + mfcTagDetails.getDump());
                classic = new Classic(mfc);
/*
                // brute force method to check for known default authentication keys
                int numberOfSuccessAuths = classic.checkDefaultAuthentication();
                writeToUiAppend("number of successful authentications: " + numberOfSuccessAuths);
                byte[][] authKeyMatrix = classic.getAuthenticationKeyMatrix();
                String[] authKeyTypeMatrix = classic.getAuthenticationKeyTypeMatrix();
                for (int i = 0; i < mfcTagDetails.getSectorCount(); i++) {
                    writeToUiAppend("sector: " + String.format("%02d", i) + ":" + Utils.bytesToHexNpe(authKeyMatrix[i]));
                }
                writeToUiAppend("Note: NULL means no default key found");

                byte[] sectorRead = classic.readSector(0, authKeyMatrix[0], authKeyTypeMatrix[0]);
                writeToUiAppend("keyType: " + authKeyTypeMatrix[0]);
                writeToUiAppend("sector 00: " +Utils.printData("data", sectorRead));
                writeToUiAppend("errorCode: " + classic.getErrorCode() + " " + classic.getErrorCodeReason());

                // public SectorMcModel(int sectorNumber, byte[] sectorRead, String keyType, byte[] key) {
                SectorMcModel sectorMc = new SectorMcModel(0, sectorRead, authKeyTypeMatrix[0], authKeyMatrix[0]);
                if (sectorMc.isDataIsValid())
                writeToUiAppend(sectorMc.dump());
*/
                vibrateShort();

            } else {
                writeToUiAppendBorderColor("The tag you are tapping to the reader is not of type Mifare Classic, aborted", COLOR_RED);
                return;
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
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);
/*
        MenuItem mGoToHome = menu.findItem(R.id.action_return_main);
        mGoToHome.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(MainActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });
*/
        MenuItem mAccessConditionEncoder = menu.findItem(R.id.action_access_condition_encoder);
        mAccessConditionEncoder.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                //Intent intent = new Intent(MainActivity.this, AccessConditionsEncoderActivity.class);
                Intent intent = new Intent(MainActivity.this, AccessConditionTool.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }
}