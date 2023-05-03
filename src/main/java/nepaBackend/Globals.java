package nepaBackend;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import nepaBackend.security.SecurityConstants;

public class Globals {

    public static final boolean TESTING = SecurityConstants.TEST_ENVIRONMENT;
    
    private static final String PROD_DB_BASE_URL = SecurityConstants.DB_ADDRESS;

    private static final String BIGHORN_META_INDEX_DIRECTORY_PATH = "/media/data/nepaccess/EISDoc";
    private static final String BIGHORN_INDEX_DIRECTORY_PATH = "/media/data/nepaccess/DocumentText";
    private static final String BIGHORN_SUGGEST_PATH = "/media/data/nepaccess/LuceneSuggest";

    private static final String META_INDEX_DIRECTORY_PATH = "/EISDoc";
    private static final String INDEX_DIRECTORY_PATH = "/DocumentText";
    private static final String SUGGEST_PATH = "/LuceneSuggest";
    
    private static final String TESTING_INDEX_DIRECTORY_PATH = "C:\\Lucene\\DocumentText";
    private static final String META_TESTING_INDEX_DIRECTORY_PATH = "C:\\Lucene\\EISDoc";
    private static final String TEST_SUGGEST_PATH = "C:\\Lucene\\lucene_suggest";
    
    // old test paths
//    private static final String TESTING_INDEX_DIRECTORY_PATH = "C:/lucene/nepaBackend.model.DocumentText";
//    private static final String TESTING_INDEX_DIRECTORY_PATH = "C:\\gitrepo\\uapBackend\\uapBackend\\DocumentText";
//    private static final String META_TESTING_INDEX_DIRECTORY_PATH = "C:\\gitrepo\\uapBackend\\uapBackend\\EISDoc";
    
    public static final Path getIndexPath() {
		System.out.println("TESTING: VAR IN getIndexPath "+TESTING);
    	if(TESTING) {
    		return Path.of(TESTING_INDEX_DIRECTORY_PATH);
    	} else if (SecurityConstants.BIGHORN) {
    		return Path.of(BIGHORN_INDEX_DIRECTORY_PATH);
    	} else {
    		return Path.of(INDEX_DIRECTORY_PATH);
    	}
    }
    public static final String getIndexString() {
    	if(TESTING) {
    		return (TESTING_INDEX_DIRECTORY_PATH);
    	} else if (SecurityConstants.BIGHORN) {
    		return (BIGHORN_INDEX_DIRECTORY_PATH);
    	} else {
    		return (INDEX_DIRECTORY_PATH);
    	}
    }
	public static String getMetaIndexString() {
    	if(TESTING) {
    		return (META_TESTING_INDEX_DIRECTORY_PATH);
    	} else if (SecurityConstants.BIGHORN) {
    		return (BIGHORN_META_INDEX_DIRECTORY_PATH);
    	} else {
    		return (META_INDEX_DIRECTORY_PATH);
    	}
	}
	public static Path getSuggestPath() {
		if(TESTING) {
			return Path.of(TEST_SUGGEST_PATH);
    	} else if (SecurityConstants.BIGHORN) {
    		return Path.of(BIGHORN_SUGGEST_PATH);
		} else {
			return Path.of(SUGGEST_PATH);
		}
	}

    // Database/file server URL to base folder containing all files exposed to DAL for download
	// Note: Might change this after migration
    public static final String DOWNLOAD_URL = "http://"+PROD_DB_BASE_URL+":80/test/";
    // Database/file server URL for Express service which handles new file uploads (and potentially updating or deleting files)
    public static final String UPLOAD_URL = "http://"+PROD_DB_BASE_URL+":"+SecurityConstants.EXPRESS_PORT+"/";
    
    public static final List<String> EIS_TYPES = Arrays.asList("Draft Supplement",
			"Final Supplement",
			"Second Draft Supplemental",
			"Second Draft",
			"Adoption",
			"LF",
			"Revised Final",
			"LD",
			"Third Draft Supplemental",
			"Second Final",
			"Second Final Supplemental",
			"DC",
			"FC",
			"RF",
			"RD",
			"Third Final Supplemental",
			"DD",
			"Revised Draft",
			"NF",
			"F2",
			"D2",
			"F3",
			"DE",
			"FD",
			"DF",
			"FE",
			"A3",
			"A1");
    
	/** Isn't null or blank */
	public static final boolean saneInput(String sInput) {
		if(sInput == null) {
			return false;
		}
		return (!sInput.isBlank());
	}

	public static final boolean saneInput(String[] sInput) {
		if(sInput == null || sInput.length == 0) {
			return false;
		}
		return true;
	}

	public static final boolean saneInput(boolean bInput) {
		return bInput;
	}

	// TODO: Validation for everything, like Dates
	
	public static final boolean saneInput(int iInput) {
		if(iInput > 0 && iInput <= Integer.MAX_VALUE) {
			return true;
		}
		return false;
	}
	/** if null return ""; else remove all newlines, tabs and extra spaces return ( str.replace('�', ' ').replaceAll("\\s", " ") ).strip(); */
	public static String normalizeSpace(String str) {
		if(str == null) {
			return "";
		}
		// At some point, NBSP from importing through webapp is interpreted as �, so replace with a regular space, then normalize other whitespace.
		// Need the + to remove double spaces (or more), or else each individual space is replaced with a space, which doesn't help
		return ( str.replace('�', ' ')
				.replace('\t', ' ') // Replace all tabs with spaces
				.replaceAll("\\R","") // Remove all newlines
				.replaceAll("\\s+", " ") ).strip(); // Reduce all spaces to one space and then trim
	}
	
	public static Boolean validPassword(String pass) {
		if(pass != null && pass.length() >= 4 && pass.length() <= 50) {
			return true;
		} else {
			return false;
		}
	}


	// Note: Can also have a backup URL set up for use if primary fails
}
