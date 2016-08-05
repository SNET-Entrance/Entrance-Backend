package integration;

import java.io.File;

public class FileOverwriteMitigation {

    /**
     * Finds an unused file name by adding some ever increasing counter
     * according the following format:
     * <p><code>"{{filename}} [i].{{ext}}"</code></p> or
     * <p><code>"{{filename}} [i]"</code></p> if there is no extension.
     * <p>This doesn't handle split second claiming of the file name by
     * other processes in the time between finding a free file name and
     * actually writing to it.</p>
     * @param filepath    Absolute or relative file path without the dot or
     *                    extension
     * @param ext         If <code>null</code> is passed, it is assumed that
     *                    there is no extension
     * @return  Free writable file (most likely)
     */
    public static File findFreeFileName(String filepath, String ext) {
        File base;
        if (ext == null) {
            base = new File(filepath);
        } else {
            base = new File(filepath + "." + ext);
        }

        int i = 1;
        while (base.exists()) {
            if (ext == null) {
                base = new File(filepath + " [" + i + "]");
            } else {
                base = new File(filepath + " [" + i + "]." + ext);
            }
            i++;
        }
        return base;
    }

    public static File findFreeFileName(File filepath) {
        String[] split = splitFilenameIntoFilepathAndExtension(filepath.getAbsolutePath());
        return findFreeFileName(split[0], split[1]);
    }

    /**
     * Splits a given file path into its file path without the extension and a
     * separate extension. The pair is returned as array. If the second element
     * is <code>null</code>, then there was no extension to be found.
     * @param filepath    Absolute or relative file path
     * @return Array of the file path and extension separately
     */
    public static String[] splitFilenameIntoFilepathAndExtension(String filepath){
        int dotIndex = filepath.lastIndexOf(".");
        int slashIndex = filepath.lastIndexOf("/");
        int backslashIndex = filepath.lastIndexOf("\\");
        if (dotIndex < slashIndex && dotIndex < backslashIndex) {
            dotIndex = -1;
        }
        if (dotIndex == -1) {
            return new String[]{filepath, null};
        } else {
            return new String[]{ filepath.substring(0, dotIndex), filepath.substring(dotIndex+1) };
        }
    }
}
