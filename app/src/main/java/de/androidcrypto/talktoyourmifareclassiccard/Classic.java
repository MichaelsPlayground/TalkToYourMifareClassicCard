package de.androidcrypto.talktoyourmifareclassiccard;

import android.nfc.tech.MifareClassic;
import android.nfc.tech.NfcA;
import android.util.Log;

import java.io.IOException;
import java.util.List;

/**
 * This class takes all commands for Mifare Classic usage
 */

public class Classic {
    private static final String TAG = Classic.class.getName();
    private NfcA nfcA = null;
    private final MifareClassic mfc;
    private final MifareClassicTagDetails tagDetails;
    private int numberOfSectors;

    private byte READ_ONE_BLOCK_COMMAND = (byte) 0x30;

    public static final byte[] MIFARE_DEFAULT_KEY = MifareClassic.KEY_DEFAULT;
    // KEY_DEFAULT: ffffffffffff
    public static final byte[] MIFARE_DEFAULT_KEY_APPLICATION_DIRECTORY = MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY;
    // KEY_APPLICATION_DIRECTORY: a0a1a2a3a4a5
    public static final byte[] MIFARE_DEFAULT_KEY_NFC_FORUM = MifareClassic.KEY_NFC_FORUM;
    // KEY_NFC_FORUM: d3f7d3f7d3f7
    private byte[][] authenticationKeyMatrix; // takes the authentication keys for each sector of the tag
    private String[] authenticationKeyTypeMatrix; // takes 'A' or 'B' depending on authentication success, if '' no success
    private String[] authenticationKeySourceMatrix; // takes the name of default keys or is blank
    public static final String KEY_TYPE_A = "A";
    public static final String KEY_TYPE_B = "B";

    public static final int ERROR_OK = 0;
    public static final int ERROR_WRONG_PARAMETER = 1;
    public static final int ERROR_MISSING_AUTHENTICATION = 2;
    public static final int ERROR_IOEXCEPTION = 10;
    private int errorCode = -1;
    private final String ERROR_CODE_REASON_OK = "OK";
    private final String ERROR_CODE_REASON_MISSING_AUTHENTICATION = "Failure: missing authentication";
    private String errorCodeReason = "FAILURE";


    public Classic(MifareClassic mfc) {
        this.mfc = mfc;
        this.tagDetails = new MifareClassicTagDetails(mfc);
        if (mfc == null) {
            Log.e(TAG, "mfc is NULL, aborted");
            return;
        }
        this.numberOfSectors = tagDetails.getSectorCount();
        authenticationKeyMatrix = new byte[this.numberOfSectors][];
        authenticationKeyTypeMatrix = new String[this.numberOfSectors];
        authenticationKeySourceMatrix = new String[this.numberOfSectors];
    }

    /**
     * Brute force method to check the authentication with all default keys
     * @return the number of successful authentications
     */
    public int checkDefaultAuthentication() {
        boolean success;
        int numberOfSuccessAuthentications = 0;
        for (int sectorNumber = 0; sectorNumber < numberOfSectors; sectorNumber++) {
            success = false;
            if (!success) {
                success = authenticateSectorWithKeyA(sectorNumber, MIFARE_DEFAULT_KEY);
                if (success) {
                    numberOfSuccessAuthentications++;
                    authenticationKeyMatrix[sectorNumber] = MIFARE_DEFAULT_KEY.clone();
                    authenticationKeyTypeMatrix[sectorNumber] = KEY_TYPE_A;
                    authenticationKeySourceMatrix[sectorNumber] = "MIFARE_DEFAULT_KEY";
                }
            }
            if (!success) {
                success = authenticateSectorWithKeyA(sectorNumber, MIFARE_DEFAULT_KEY_APPLICATION_DIRECTORY);
                if (success) {
                    numberOfSuccessAuthentications++;
                    authenticationKeyMatrix[sectorNumber] = MIFARE_DEFAULT_KEY_APPLICATION_DIRECTORY.clone();
                    authenticationKeyTypeMatrix[sectorNumber] = KEY_TYPE_A;
                    authenticationKeySourceMatrix[sectorNumber] = "MIFARE_DEFAULT_KEY_APPLICATION_DIRECTORY";
                }
            }
            if (!success) {
                success = authenticateSectorWithKeyA(sectorNumber, MIFARE_DEFAULT_KEY_NFC_FORUM);
                if (success) {
                    numberOfSuccessAuthentications++;
                    authenticationKeyMatrix[sectorNumber] = MIFARE_DEFAULT_KEY_NFC_FORUM.clone();
                    authenticationKeyTypeMatrix[sectorNumber] = KEY_TYPE_A;
                    authenticationKeySourceMatrix[sectorNumber] = "MIFARE_DEFAULT_KEY_NFC_FORUM";
                }
            }
            if (!success) {
                success = authenticateSectorWithKeyB(sectorNumber, MIFARE_DEFAULT_KEY);
                if (success) {
                    numberOfSuccessAuthentications++;
                    authenticationKeyMatrix[sectorNumber] = MIFARE_DEFAULT_KEY.clone();
                    authenticationKeyTypeMatrix[sectorNumber] = KEY_TYPE_B;
                    authenticationKeySourceMatrix[sectorNumber] = "MIFARE_DEFAULT_KEY";
                }
            }
            if (!success) {
                success = authenticateSectorWithKeyB(sectorNumber, MIFARE_DEFAULT_KEY_APPLICATION_DIRECTORY);
                if (success) {
                    numberOfSuccessAuthentications++;
                    authenticationKeyMatrix[sectorNumber] = MIFARE_DEFAULT_KEY_APPLICATION_DIRECTORY.clone();
                    authenticationKeyTypeMatrix[sectorNumber] = KEY_TYPE_B;
                    authenticationKeySourceMatrix[sectorNumber] = "MIFARE_DEFAULT_KEY_APPLICATION_DIRECTORY";
                }
            }
            if (!success) {
                success = authenticateSectorWithKeyB(sectorNumber, MIFARE_DEFAULT_KEY_NFC_FORUM);
                if (success) {
                    numberOfSuccessAuthentications++;
                    authenticationKeyMatrix[sectorNumber] = MIFARE_DEFAULT_KEY_NFC_FORUM.clone();
                    authenticationKeyTypeMatrix[sectorNumber] = KEY_TYPE_B;
                    authenticationKeySourceMatrix[sectorNumber] = "MIFARE_DEFAULT_KEY_NFC_FORUM";
                }
            }
        }
        errorCode = ERROR_OK;
        errorCodeReason = ERROR_CODE_REASON_OK;
        return numberOfSuccessAuthentications;
    }

    public boolean authenticateSectorWithKeyA(int sectorNumber, byte[] key) {
        try {
            errorCode = ERROR_OK;
            errorCodeReason = ERROR_CODE_REASON_OK;
            return mfc.authenticateSectorWithKeyA(sectorNumber, key);
        } catch (IOException e) {
            Log.e(TAG, "IOException: " + e.getMessage());
            errorCode = ERROR_IOEXCEPTION;
            errorCodeReason = "IOEXCEPTION: " + e.getMessage();
            return false;
        }
    }

    public boolean authenticateSectorWithKeyB(int sectorNumber, byte[] key) {
        try {
            errorCode = ERROR_OK;
            errorCodeReason = ERROR_CODE_REASON_OK;
            return mfc.authenticateSectorWithKeyB(sectorNumber, key);
        } catch (IOException e) {
            Log.e(TAG, "IOException: " + e.getMessage());
            errorCode = ERROR_IOEXCEPTION;
            errorCodeReason = "IOEXCEPTION: " + e.getMessage();
            return false;
        }
    }

    public boolean authenticateSectorWithKey(int sectorNumber, byte[] key, String keyType) {
        if (keyType.equals(KEY_TYPE_A)) {
            return authenticateSectorWithKeyA(sectorNumber, key);
        } else {
            return authenticateSectorWithKeyB(sectorNumber, key);
        }
    }

    public String authenticateSectorWithKey (int sectorNumber, byte[] key){
        boolean success = authenticateSectorWithKeyA(sectorNumber, key);
        if (success) {
            return "A";
        } else {
            success = authenticateSectorWithKeyB(sectorNumber, key);
            if (success) {
                return "B";
            } else {
                return "";
            }
        }
    }

    public byte[] readSector(int sectorNumber, byte[] key, String keyType) {
        Log.d(TAG, "readSector: " + sectorNumber);
        // sanity checks
        if ((sectorNumber < 0) || (sectorNumber > (numberOfSectors - 1))) {
            errorCode = ERROR_WRONG_PARAMETER;
            errorCodeReason = "Wrong parameter (sectorNumber not in range 0.." + (numberOfSectors - 1) + "), aborted";
            return null;
        }
        if ((key == null) || (key.length != 6)) {
            errorCode = ERROR_WRONG_PARAMETER;
            errorCodeReason = "Wrong parameter (key is NULL or not of length 6), aborted";
            return null;
        }
        if ((!keyType.equals(KEY_TYPE_A)) && (!keyType.equals(KEY_TYPE_B))) {
            errorCode = ERROR_WRONG_PARAMETER;
            errorCodeReason = "Wrong parameter (keyType is not A or B), aborted";
            return null;
        }
        boolean authSuccess = false;
        if (keyType.equals("A")) {
            authSuccess = authenticateSectorWithKeyA(sectorNumber, key);
            if (authSuccess) {
                authenticationKeyMatrix[sectorNumber] = key;
                authenticationKeyTypeMatrix[sectorNumber] = KEY_TYPE_A;
            }
        } else {
            authSuccess = authenticateSectorWithKeyB(sectorNumber, key);
            if (authSuccess) {
                authenticationKeyMatrix[sectorNumber] = key;
                authenticationKeyTypeMatrix[sectorNumber] = KEY_TYPE_B;
            }
        }
        if (!authSuccess) {
            authenticationKeyTypeMatrix[sectorNumber] = "";
            errorCode = ERROR_MISSING_AUTHENTICATION;
            errorCodeReason = ERROR_CODE_REASON_MISSING_AUTHENTICATION;
            return null;
        }
        byte[] dataBytes = new byte[64]; // takes the data of all 4 blocks
        try {
            int block_index = mfc.sectorToBlock(sectorNumber);
            // get block in sector
            int blocksInSector = mfc.getBlockCountInSector(sectorNumber);
            // get the data of each block
            dataBytes = new byte[(16 * blocksInSector)];
            for (int blockInSectorCount = 0; blockInSectorCount < blocksInSector; blockInSectorCount++) {
                // get following data
                byte[] block = new byte[0];
                block = mfc.readBlock((block_index + blockInSectorCount));
                System.arraycopy(block, 0, dataBytes, (blockInSectorCount * 16), 16);
            }
            return dataBytes;
        } catch (IOException e) {
            Log.e(TAG, "IOException: " + e.getMessage());
            errorCode = ERROR_IOEXCEPTION;
            errorCodeReason = "IOEXCEPTION: " + e.getMessage();
            return null;
        }

    }


    public byte[] readOneBlock(int blockNumber, byte[] key) {
        byte[] block;
        int secCnt = mfc.blockToSector(blockNumber);
        System.out.println("readBlock for block " + blockNumber + " is in sector " + secCnt);
        try {
            mfc.authenticateSectorWithKeyB(secCnt, key);
            block = mfc.readBlock(blockNumber);
        } catch (IOException e) {
            //throw new RuntimeException(e);
            System.out.println("RuntimeException: " + e.getMessage());
            return null;
        }
        return block;
    }


    /**
     * section for getters
     */

    public MifareClassicTagDetails getTagDetails() {
        return tagDetails;
    }

    public byte getREAD_ONE_BLOCK_COMMAND() {
        return READ_ONE_BLOCK_COMMAND;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public String getErrorCodeReason() {
        return errorCodeReason;
    }

    public byte[][] getAuthenticationKeyMatrix() {
        return authenticationKeyMatrix;
    }

    public String[] getAuthenticationKeyTypeMatrix() {
        return authenticationKeyTypeMatrix;
    }

    public String[] getAuthenticationKeySourceMatrix() {
        return authenticationKeySourceMatrix;
    }
}
