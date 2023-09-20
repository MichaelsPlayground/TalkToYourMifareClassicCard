/*
 * Copyright 2013 Gerhard Klostermeier
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


package de.androidcrypto.talktoyourmifareclassiccard;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;


/**
 * Decode MIFARE Classic Access Conditions from their hex format
 * to a more human readable format and vice versa.
 * @author Gerhard Klostermeier
 * Source: MIFARE Classic Tool (MCT), https://github.com/ikarus23/MifareClassicTool/tree/master
 * LICENSE: GNU General Public License v3.0
 */
public class AccessConditionTool extends AppCompatActivity {

    private EditText mAC;
    private Button[] mBlockButtons;
    private boolean mWasKeyBReadable;
    /**
     * True if the Access Conditions of the Sector Trailer state that key B
     * is readable. Many methods rely on this member variable
     * ({@link #getResourceForDataBlocksByRowNr(int)},
     * {@link #getResourceForSectorTrailersByRowNr(int)},
     * {@link #acRowNrToACBits(int, boolean)},
     * {@link #acBitsToACRowNr(byte[], boolean)},
     * {@link #buildDataBlockDialog(boolean)}).
     */
    private boolean mIsKeyBReadable;
    /**
     * Matrix of access conditions bits (C1-C3) where the first
     * dimension is the "C" parameter (C1-C3, Index 0-2) and the second
     * dimension is the block number (Index 0-3).
     * This matrix will be updated each time a user chooses an Access Condition
     * via {@link #mDataBlockDialog} or {@link #mSectorTrailerDialog}
     */
    private byte[][] mACMatrix;
    /**
     * The last clicked "choose Access Conditions for data block"-button.
     * @see #onChooseACforDataBock(View)
     */
    private Button mSelectedButton;
    /**
     * A dialog which allow the user to choose between all possible
     * Access Conditions for a data block.
     */
    private AlertDialog mDataBlockDialog;
    /**
     * A dialog which allow the user to choose between all possible
     * Access Conditions for a Sector Trailer.
     */
    private AlertDialog mSectorTrailerDialog;

    /**
     * Build the two dialogs for choosing the Access Conditions
     * ({@link #mDataBlockDialog} and {@link #mSectorTrailerDialog}) and
     * initialize the some member variables.
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_access_condition_tool);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        // Init. member vars.
        mAC = findViewById(R.id.editTextAccessConditionToolAC);
        mBlockButtons = new Button[4];
        mBlockButtons[0] = findViewById(
                R.id.buttonAccessConditionToolBlock0);
        mBlockButtons[1] = findViewById(
                R.id.buttonAccessConditionToolBlock1);
        mBlockButtons[2] = findViewById(
                R.id.buttonAccessConditionToolBlock2);
        mBlockButtons[3] = findViewById(
                R.id.buttonAccessConditionToolBlock3);
        // Init AC matrix with factory setting/transport configuration.
        mACMatrix = new byte[][] {
                {0, 0, 0, 0},
                {0, 0, 0, 0},
                {0, 0, 0, 1} };

        // Build the dialog with Access Conditions for the Sector Trailer.
        String[] items = new String[8];
        for (int i = 0; i < 8; i++) {
            items[i] = getString(getResourceForSectorTrailersByRowNr(i));
        }
        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                this, R.layout.list_item_small_text, items);

        ListView lv = new ListView(this);
        lv.setAdapter(adapter);
        lv.setOnItemClickListener(
                (parent, view, position, id) -> {
                    // Change button text to selected Access Conditions.
                    mBlockButtons[3].setText(getString(
                            getResourceForSectorTrailersByRowNr(position)));
                    // Set Access Condition bits for sector trailer.
                    byte[] acBits = acRowNrToACBits(position, true);
                    mACMatrix[0][3] = acBits[0];
                    mACMatrix[1][3] = acBits[1];
                    mACMatrix[2][3] = acBits[2];
                    // Rebuild the data block dialog based on the readability of
                    // key B.
                    mIsKeyBReadable = position < 2 || position == 4;
                    buildDataBlockDialog(true);
                    // Close dialog.
                    mSectorTrailerDialog.dismiss();
                });
        mSectorTrailerDialog = new AlertDialog.Builder(this)
                .setTitle("Choose Access Conditions")
                .setView(lv)
                .create();

        // Build the dialog with Access Conditions for data blocks.
        // Key B is readable in the default configuration.
        mIsKeyBReadable = true;
        buildDataBlockDialog(false);
    }

    /**
     * Convert the 3 Access Condition bytes into a more human readable format
     * using {@link #acBytesToACMatrix(byte[])},
     * {@link #acBitsToACRowNr(byte[], boolean)},
     * {@link #getResourceForDataBlocksByRowNr(int)} and
     * {@link #getResourceForSectorTrailersByRowNr(int)}.
     * @param view The View object that triggered the method
     * (in this case the decode button).
     * @see #acBytesToACMatrix(byte[])
     * @see #acBitsToACRowNr(byte[], boolean)
     * @see #getResourceForDataBlocksByRowNr(int)
     * @see #getResourceForDataBlocksByRowNr(int)
     * @see #mACMatrix
     */
    public void onDecode(View view) {
        String ac = mAC.getText().toString();
        if (ac.length() != 6) {
            // Error. Access Conditions are not 3 byte (6 characters) long.
            Toast.makeText(this, "Error: Access Conditions have to be 3 bytes (6 characters) long",
                    Toast.LENGTH_LONG).show();
            return;
        }
        if (!ac.matches("[0-9A-Fa-f]+")) {
            // Error. Not hex.
            Toast.makeText(this, "Error: Access Conditions are not hex (0-9, A-F)",
                    Toast.LENGTH_LONG).show();
            return;
        }

        byte[][] acMatrix = acBytesToACMatrix(
                //Common.hex2Bytes(ac));
                Utils.hexStringToByteArray(ac));
        boolean error = false;
        if (acMatrix != null) {
            // First check & set Sector Trailer.
            byte[] acBits = {acMatrix[0][3], acMatrix[1][3], acMatrix[2][3]};
            int rowNr = acBitsToACRowNr(acBits, true);
            if (rowNr != -1) {
                // Check if key B is readable.
                mIsKeyBReadable = rowNr < 2 || rowNr == 4;
                mBlockButtons[3].setText(getString(
                        getResourceForSectorTrailersByRowNr(rowNr)));

                // Now check & set Data blocks.
                for (int i = 0; i < 3; i++) {
                    acBits = new byte [] {acMatrix[0][i], acMatrix[1][i],
                            acMatrix[2][i]};
                    rowNr = acBitsToACRowNr(acBits, false);
                    if (rowNr == -1) {
                        // Error.
                        error = true;
                        break;
                    }
                    mBlockButtons[i].setText(getString(
                            getResourceForDataBlocksByRowNr(rowNr)));
                }
            } else {
                // Error.
                error = true;
            }
        } else {
            // Error.
            error = true;
        }

        // Were there some error during this process?
        if (error) {
            // Display an error message.
            Toast.makeText(this, "Error: The access conditions are invalid",
                    Toast.LENGTH_LONG).show();
            return;
        }
        mACMatrix = acMatrix;
        buildDataBlockDialog(false);
    }

    /**
     * Convert the {@link #mACMatrix} to 3 Access Condition bytes using
     * {acMatrixToACBytes(byte[][])} and display them.
     * @param view The View object that triggered the method
     * (in this case the encode button).
     * @see #acMatrixToACBytes(byte[][])
     * @see #mACMatrix
     * @see #acRowNrToACBits(int, boolean)
     */
    public void onEncode(View view) {
        //mAC.setText(Common.bytes2Hex(acMatrixToACBytes(mACMatrix)));
        mAC.setText(Utils.bytesToHexNpe(acMatrixToACBytes(mACMatrix)));
    }

    /**
     * Backup the button which triggered this method to {@link #mSelectedButton}
     * to change its text later and show the Access Condition chooser dialog
     * for data blocks ({@link #mDataBlockDialog}).
     * @param view The View object that triggered the method
     * (in this case one of the data block buttons).
     * @see #mDataBlockDialog
     * @see #mSelectedButton
     */
    public void onChooseACforDataBock(View view) {
        mSelectedButton = (Button) view;
        mDataBlockDialog.show();
    }

    /**
     * Show the Access Condition chooser dialog for Sector Trailers
     * ({@link #mSectorTrailerDialog}).
     * @param view The View object that triggered the method
     * (in this case the Sector Trailer button).
     * @see #mSectorTrailerDialog
     */
    public void onChooseACforSectorTrailer(View view) {
        mSectorTrailerDialog.show();
    }

    /**
     * Copy the MIFARE Classic Access Conditions to the Android clipboard.
     * @param view The View object that triggered the method
     * (in this case the copy button).
     */
    public void onCopyToClipboard(View view) {
        Clipboard.copyToClipboard(mAC.getText().toString(), this, true);
    }

    /**
     * Paste the content of the Android clipboard (if plain text) to the
     * access conditions edit text.
     * @param view The View object that triggered the method
     * (in this case the paste button).
     */
    public void onPasteFromClipboard(View view) {
        String text = Clipboard.getFromClipboard(this);
        if (text != null) {
            mAC.setText(text);
        }
    }

    /**
     * Return the resource ID of an Access Condition string for data
     * blocks based on its position in the table
     * (see: res/values/access_conditions.xml and
     * NXP's MF1S50yyX, Chapter 8.7.1, 8.7.2, 8.7.3, Table 7 and 8).
     * @param rowNr Row number of the Access Condition table.
     * @return The resource ID of an Access Condition string.
     * @see #mIsKeyBReadable
     */
    private int getResourceForDataBlocksByRowNr(int rowNr) {
        String prefix = "ac_data_block_";
        if (mIsKeyBReadable) {
            prefix = "ac_data_block_no_keyb_";
        }
        return getResourceForAccessCondition(prefix, rowNr);
    }

    /**
     * Return the resource ID of an Access Condition string for Sector
     * Trailers based on its position in the table
     * (see: res/values/access_conditions.xml and
     * NXP's MF1S50yyX, Chapter 8.7.1, 8.7.2, 8.7.3, Table 7 and 8).
     * @param rowNr Row number of the Access Condition table.
     * @return The resource ID of an Access Condition string.
     * @see #mIsKeyBReadable
     */
    private int getResourceForSectorTrailersByRowNr(int rowNr) {
        return getResourceForAccessCondition("ac_sector_trailer_", rowNr);
    }

    /**
     * A helper function for {@link #getResourceForDataBlocksByRowNr(int)} and
     * {@link #getResourceForSectorTrailersByRowNr(int)}.
     * @param prefix The prefix of the resource name
     * ("ac_data_block_", "ac_data_block_no_keyb_" or "ac_sector_trailer_").
     * @param rowNr Row number of the Access Condition table.
     * @return The resource ID of an Access Condition string.
     */
    private int getResourceForAccessCondition(String prefix, int rowNr) {
        int returnInt = getResources().getIdentifier(
                prefix + rowNr, "string", getPackageName());
        return returnInt;
    }
    private int getResourceForAccessConditionOrg(String prefix, int rowNr) {
        return getResources().getIdentifier(
                prefix + rowNr, "string", getPackageName());
    }

    /**
     * Convert the the row number of the Access Condition table to its
     * corresponding access bits C1, C2 and C3
     * (see: res/values/access_conditions.xml and
     * NXP's MF1S50yyX, Chapter 8.7.1, 8.7.2, 8.7.3, Table 7 and 8).
     * @param rowNr The row number of the Access Condition table (0-7).
     * @param isSectorTrailer True if the row number refers to a Sector Trailer.
     * @return The access bits C1, C2 and C3. On error null will be returned.
     * @see #mIsKeyBReadable
     */
    private byte[] acRowNrToACBits(int rowNr, boolean isSectorTrailer) {
        if (!isSectorTrailer && mIsKeyBReadable && rowNr > 1) {
            switch (rowNr) {
            case 2:
                return new byte[] {0, 0, 1};
            case 3:
                return new byte[] {1, 1, 1};
            default:
                return null;
            }
        }

        switch (rowNr) {
        case 0:
            return new byte[] {0, 0, 0};
        case 1:
            return new byte[] {0, 1, 0};
        case 2:
            return new byte[] {1, 0, 0};
        case 3:
            return new byte[] {1, 1, 0};
        case 4:
            return new byte[] {0, 0, 1};
        case 5:
            return new byte[] {0, 1, 1};
        case 6:
            return new byte[] {1, 0, 1};
        case 7:
            return new byte[] {1, 1, 1};
        default:
            // Error.
            return null;
        }
    }

    /**
     * Convert the access bits C1, C2 and C3 to its corresponding row number
     * in the Access Condition table (see: res/values/access_conditions.xml and
     * NXP's MF1S50yyX, Chapter 8.7.1, 8.7.2, 8.7.3, Table 7 and 8).
     * @param acBits The access bits C1, C2 and C3.
     * @param isSectorTrailer True if the row number refers to a Sector Trailer.
     * @return The row number of the Access Condition table. On error -1 will
     * be returned.
     * @see #mIsKeyBReadable
     */
    private int acBitsToACRowNr(byte[] acBits, boolean isSectorTrailer) {
        if (acBits != null && acBits.length != 3) {
            return -1;
        }

        if (!isSectorTrailer && mIsKeyBReadable) {
            if (acBits[0] == 0 && acBits[1] == 0 && acBits[2] == 0) {
                return 0;
            } else if (acBits[0] == 0 && acBits[1] == 1 && acBits[2] == 0) {
                return 1;
            } else if (acBits[0] == 0 && acBits[1] == 0 && acBits[2] == 1) {
                return 2;
            } else if (acBits[0] == 1 && acBits[1] == 1 && acBits[2] == 1) {
                return 3;
            }
        } else {
            if (acBits[0] == 0 && acBits[1] == 0 && acBits[2] == 0) {
                return 0;
            } else if (acBits[0] == 0 && acBits[1] == 1 && acBits[2] == 0) {
                return 1;
            } else if (acBits[0] == 1 && acBits[1] == 0 && acBits[2] == 0) {
                return 2;
            } else if (acBits[0] == 1 && acBits[1] == 1 && acBits[2] == 0) {
                return 3;
            } else if (acBits[0] == 0 && acBits[1] == 0 && acBits[2] == 1) {
                return 4;
            } else if (acBits[0] == 0 && acBits[1] == 1 && acBits[2] == 1) {
                return 5;
            } else if (acBits[0] == 1 && acBits[1] == 0 && acBits[2] == 1) {
                return 6;
            } else if (acBits[0] == 1 && acBits[1] == 1 && acBits[2] == 1) {
                return 7;
            }
        }

        // Error.
        return -1;
    }

    /**
     * Rebuild the {@link #mDataBlockDialog} based on {@link #mIsKeyBReadable}.
     * If key B is readable due to the Access Conditions of a Sector Trailer,
     * the Access Conditions for a normal data block are limited to
     * conditions that don't use key B.
     * @param resetBlockACs If True the Access Conditions of all data blocks
     * will be reseted (C1=0, C2=0, C3=0).
     * @see #mDataBlockDialog
     * @see #mIsKeyBReadable
     */
    private void buildDataBlockDialog(boolean resetBlockACs) {
        String[] items;
        if (mIsKeyBReadable && !mWasKeyBReadable) {
            // Rebuild dialog (because key B is now readable).
            items = new String[4];
            for (int i = 0; i < 4; i++) {
                items[i] = getString(getResourceForDataBlocksByRowNr(i));
            }
            mWasKeyBReadable = true;
        } else if (!mIsKeyBReadable && mWasKeyBReadable){
            // Rebuild dialog (because key B is no longer readable).
            items = new String[8];
            for (int i = 0; i < 8; i++) {
                items[i] = getString(getResourceForDataBlocksByRowNr(i));
            }
            mWasKeyBReadable = false;
        } else {
            // No build is needed.
            return;
        }

        if (resetBlockACs) {
            // Reset mACMatrix and update button text.
            for (int i = 0; i < 3; i++) {
                mBlockButtons[i].setText(items[0]);

                mACMatrix[0][i] = 0;
                mACMatrix[1][i] = 0;
                mACMatrix[2][i] = 0;
            }
            String r;
            //int r;
            if (mIsKeyBReadable) {
                r = "Key B is readable.\n" + "ACs of data blocks have been updated.";
            } else {
                r = "Key B is not readable.\nACs of data blocks have been updated.";
            }
            Toast.makeText(this, r, Toast.LENGTH_LONG).show();
        }

        ListAdapter adapter = new ArrayAdapter<>(
                this, R.layout.list_item_small_text, items);
        ListView lv = new ListView(this);
        lv.setAdapter(adapter);
        lv.setOnItemClickListener(
                (parent, view, position, id) -> {
                    // Change button text to selected Access Conditions.
                    mSelectedButton.setText(getString(
                            getResourceForDataBlocksByRowNr(position)));
                    // Set Access Condition bits for this block.
                    byte[] acBits = acRowNrToACBits(position, false);
                    int blockNr = Integer.parseInt(
                            mSelectedButton.getTag().toString());
                    mACMatrix[0][blockNr] = acBits[0];
                    mACMatrix[1][blockNr] = acBits[1];
                    mACMatrix[2][blockNr] = acBits[2];
                    // Close dialog.
                    mDataBlockDialog.dismiss();
                });
        mDataBlockDialog =  new AlertDialog.Builder(this)
                .setTitle("Choose Access Conditions")
                .setView(lv)
                .create();
    }

    /**
     * section for options menu, added by AndroidCrypto
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_return_home, menu);

        MenuItem mGoToHome = menu.findItem(R.id.action_return_main);
        mGoToHome.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(AccessConditionTool.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

    /**
     * methods copied from Common.java class
     */

    /**
     * Convert the Access Condition bytes to a matrix containing the
     * resolved C1, C2 and C3 for each block.
     * @param acBytes The Access Condition bytes (3 byte).
     * @return Matrix of access conditions bits (C1-C3) where the first
     * dimension is the "C" parameter (C1-C3, Index 0-2) and the second
     * dimension is the block number (Index 0-3). If the ACs are incorrect
     * null will be returned.
     */
    public static byte[][] acBytesToACMatrix(byte[] acBytes) {
        if (acBytes == null) {
            return null;
        }
        // ACs correct?
        // C1 (Byte 7, 4-7) == ~C1 (Byte 6, 0-3) and
        // C2 (Byte 8, 0-3) == ~C2 (Byte 6, 4-7) and
        // C3 (Byte 8, 4-7) == ~C3 (Byte 7, 0-3)
        byte[][] acMatrix = new byte[3][4];
        if (acBytes.length > 2 &&
                (byte)((acBytes[1]>>>4)&0x0F)  ==
                        (byte)((acBytes[0]^0xFF)&0x0F) &&
                (byte)(acBytes[2]&0x0F) ==
                        (byte)(((acBytes[0]^0xFF)>>>4)&0x0F) &&
                (byte)((acBytes[2]>>>4)&0x0F)  ==
                        (byte)((acBytes[1]^0xFF)&0x0F)) {
            // C1, Block 0-3
            for (int i = 0; i < 4; i++) {
                acMatrix[0][i] = (byte)((acBytes[1]>>>4+i)&0x01);
            }
            // C2, Block 0-3
            for (int i = 0; i < 4; i++) {
                acMatrix[1][i] = (byte)((acBytes[2]>>>i)&0x01);
            }
            // C3, Block 0-3
            for (int i = 0; i < 4; i++) {
                acMatrix[2][i] = (byte)((acBytes[2]>>>4+i)&0x01);
            }
            return acMatrix;
        }
        return null;
    }

    /**
     * Convert a matrix with Access Conditions bits into normal 3
     * Access Condition bytes.
     * @param acMatrix Matrix of access conditions bits (C1-C3) where the first
     * dimension is the "C" parameter (C1-C3, Index 0-2) and the second
     * dimension is the block number (Index 0-3).
     * @return The Access Condition bytes (3 byte).
     */
    public static byte[] acMatrixToACBytes(byte[][] acMatrix) {
        if (acMatrix != null && acMatrix.length == 3) {
            for (int i = 0; i < 3; i++) {
                if (acMatrix[i].length != 4)
                    // Error.
                    return null;
            }
        } else {
            // Error.
            return null;
        }
        byte[] acBytes = new byte[3];
        // Byte 6, Bit 0-3.
        acBytes[0] = (byte)((acMatrix[0][0]^0xFF)&0x01);
        acBytes[0] |= (byte)(((acMatrix[0][1]^0xFF)<<1)&0x02);
        acBytes[0] |= (byte)(((acMatrix[0][2]^0xFF)<<2)&0x04);
        acBytes[0] |= (byte)(((acMatrix[0][3]^0xFF)<<3)&0x08);
        // Byte 6, Bit 4-7.
        acBytes[0] |= (byte)(((acMatrix[1][0]^0xFF)<<4)&0x10);
        acBytes[0] |= (byte)(((acMatrix[1][1]^0xFF)<<5)&0x20);
        acBytes[0] |= (byte)(((acMatrix[1][2]^0xFF)<<6)&0x40);
        acBytes[0] |= (byte)(((acMatrix[1][3]^0xFF)<<7)&0x80);
        // Byte 7, Bit 0-3.
        acBytes[1] = (byte)((acMatrix[2][0]^0xFF)&0x01);
        acBytes[1] |= (byte)(((acMatrix[2][1]^0xFF)<<1)&0x02);
        acBytes[1] |= (byte)(((acMatrix[2][2]^0xFF)<<2)&0x04);
        acBytes[1] |= (byte)(((acMatrix[2][3]^0xFF)<<3)&0x08);
        // Byte 7, Bit 4-7.
        acBytes[1] |= (byte)((acMatrix[0][0]<<4)&0x10);
        acBytes[1] |= (byte)((acMatrix[0][1]<<5)&0x20);
        acBytes[1] |= (byte)((acMatrix[0][2]<<6)&0x40);
        acBytes[1] |= (byte)((acMatrix[0][3]<<7)&0x80);
        // Byte 8, Bit 0-3.
        acBytes[2] = (byte)(acMatrix[1][0]&0x01);
        acBytes[2] |= (byte)((acMatrix[1][1]<<1)&0x02);
        acBytes[2] |= (byte)((acMatrix[1][2]<<2)&0x04);
        acBytes[2] |= (byte)((acMatrix[1][3]<<3)&0x08);
        // Byte 8, Bit 4-7.
        acBytes[2] |= (byte)((acMatrix[2][0]<<4)&0x10);
        acBytes[2] |= (byte)((acMatrix[2][1]<<5)&0x20);
        acBytes[2] |= (byte)((acMatrix[2][2]<<6)&0x40);
        acBytes[2] |= (byte)((acMatrix[2][3]<<7)&0x80);

        return acBytes;
    }

}
