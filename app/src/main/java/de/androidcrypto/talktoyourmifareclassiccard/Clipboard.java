package de.androidcrypto.talktoyourmifareclassiccard;

import android.content.Context;
import android.widget.Toast;

/**
 * copy paste of text data using the clipboard
 * @author Gerhard Klostermeier
 * Source: MIFARE Classic Tool (MCT), https://github.com/ikarus23/MifareClassicTool/tree/master
 * LICENSE: GNU General Public License v3.0
 */
public class Clipboard {

    /**
     * Copy a text to the Android clipboard.
     * @param text The text that should by stored on the clipboard.
     * @param context Context of the SystemService
     * (and the Toast message that will by shown).
     * @param showMsg Show a "Copied to clipboard" message.
     */
    public static void copyToClipboard(String text, Context context,
                                       boolean showMsg) {
        if (!text.equals("")) {
            android.content.ClipboardManager clipboard =
                    (android.content.ClipboardManager)
                            context.getSystemService(
                                    Context.CLIPBOARD_SERVICE);
            android.content.ClipData clip =
                    android.content.ClipData.newPlainText(
                            "MIFARE Classic Tool data", text);
            clipboard.setPrimaryClip(clip);
            if (showMsg) {
                Toast.makeText(context, "Copied to clipboard",
                        Toast.LENGTH_SHORT).show();
            }
        }
    }

    /**
     * Get the content of the Android clipboard (if it is plain text).
     * @param context Context of the SystemService
     * @return The content of the Android clipboard. On error
     * (clipboard empty, clipboard content not plain text, etc.) null will
     * be returned.
     */
    public static String getFromClipboard(Context context) {
        android.content.ClipboardManager clipboard =
                (android.content.ClipboardManager)
                        context.getSystemService(
                                Context.CLIPBOARD_SERVICE);
        if (clipboard.getPrimaryClip() != null
                && clipboard.getPrimaryClip().getItemCount() > 0
                && clipboard.getPrimaryClipDescription().hasMimeType(
                android.content.ClipDescription.MIMETYPE_TEXT_PLAIN)
                && clipboard.getPrimaryClip().getItemAt(0) != null
                && clipboard.getPrimaryClip().getItemAt(0)
                .getText() != null) {
            return clipboard.getPrimaryClip().getItemAt(0)
                    .getText().toString();
        }

        // Error.
        return null;
    }

}
