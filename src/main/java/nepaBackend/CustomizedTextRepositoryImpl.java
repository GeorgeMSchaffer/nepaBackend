package nepaBackend;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.queryparser.classic.MultiFieldQueryParser;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.queryparser.classic.QueryParser.Operator;
import org.apache.lucene.search.IndexSearcher;
//import org.apache.lucene.search.PhraseQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.highlight.Fragmenter;
import org.apache.lucene.search.highlight.Highlighter;
import org.apache.lucene.search.highlight.InvalidTokenOffsetsException;
import org.apache.lucene.search.highlight.QueryScorer;
import org.apache.lucene.search.highlight.SimpleFragmenter;
import org.apache.lucene.search.highlight.SimpleHTMLFormatter;
import org.apache.lucene.search.highlight.TokenSources;
import org.apache.lucene.search.vectorhighlight.FastVectorHighlighter;
import org.apache.lucene.search.vectorhighlight.FieldQuery;
import org.apache.lucene.search.vectorhighlight.FragmentsBuilder;
import org.apache.lucene.search.vectorhighlight.SimpleFragListBuilder;
import org.apache.lucene.store.FSDirectory;
import org.hibernate.search.engine.ProjectionConstants;
import org.hibernate.search.jpa.FullTextEntityManager;
import org.hibernate.search.jpa.Search;
//import org.hibernate.search.query.dsl.QueryBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import nepaBackend.controller.MetadataWithContext;
import nepaBackend.controller.MetadataWithContext2;
import nepaBackend.controller.MetadataWithContext3;
import nepaBackend.enums.SearchType;
import nepaBackend.model.DocumentText;
import nepaBackend.model.EISDoc;
import nepaBackend.pojo.ReducedText;
import nepaBackend.pojo.ScoredResult;
import nepaBackend.pojo.SearchInputs;
import nepaBackend.pojo.Unhighlighted;
import nepaBackend.pojo.UnhighlightedDTO;

// TODO: Probably want a way to search for many/expanded highlights/context from one archive only
public class CustomizedTextRepositoryImpl implements CustomizedTextRepository {
	@PersistenceContext
	private EntityManager em;

	@Autowired
	JdbcTemplate jdbcTemplate;

	private static int numberOfFragmentsMin = 3;
	private static int numberOfFragmentsMax = 3;
//	private static int numberOfFragmentsMax = 5;
//	private static int fragmentSize = 250;
	private static int fragmentSize = 500;
	private static int bigFragmentSize = 1500;
	private static SimpleHTMLFormatter globalFormatter = new SimpleHTMLFormatter("<span class=\"highlight\">","</span>");
	
//	private static int fuzzyLevel = 1;

	/** Return all records matching terms in "plaintext" field (no highlights/context) 
	 * (This function is basically unused since the card format changes in Oct. '20)
	 * @throws ParseException */
	@SuppressWarnings("unchecked")
	@Override
	public List<EISDoc> search(String terms, int limit, int offset) throws ParseException {
		
		String newTerms = mutateTermModifiers(terms);
		
		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em); // Create fulltext entity manager
			
		QueryParser qp = new QueryParser("plaintext", new StandardAnalyzer());
		qp.setDefaultOperator(Operator.AND);

		// this may throw a ParseException which the caller has to deal with
		Query luceneQuery = qp.parse(newTerms);
		
		// Note: QueryBuilder, for whatever reason, doesn't treat ? like a single wildcard character.  queryparser.classic.QueryParser does.
//		QueryBuilder queryBuilder = fullTextEntityManager.getSearchFactory()
//				.buildQueryBuilder().forEntity(DocumentText.class).get();
		
		// Old code: Only good for single terms, even encapsulated in double quotes.  For multiple terms, it splits them by spaces and will basically OR them together.
//		Query luceneQuery = queryBuilder
//				.keyword()
//				.onField("plaintext")
//				.matching(terms)
//				.createQuery();
		
		// Old code: Tries to match on phrases
//		Query luceneQuery = queryBuilder
//				.phrase()
//				.onField("plaintext")
//				.sentence(terms)
//				.createQuery();
		
		// This is as loose of a search as we can build.
//		Query luceneQuery = queryBuilder
//				.keyword()
//				.fuzzy()
//				.withEditDistanceUpTo(fuzzyLevel) // max: 2; default: 2; aka maximum fuzziness
//				.onField("plaintext")
//				.matching(terms)
//				.createQuery();
		
		// Let's try an all-word search.
//		SrndQuery q = QueryParser.parse(terms);
		
//		Query luceneQuery = queryBuilder
//				.simpleQueryString()
//				.onField("plaintext")
//				.withAndAsDefaultOperator()
//				.matching(terms)
//				.createQuery();

//		String[] termsArray = org.apache.commons.lang3.StringUtils.normalizeSpace(terms).split(" ");
//		String allWordTerms = "";
//		for(int i = 0; i < termsArray.length; i++) {
//			allWordTerms += termsArray[i] + " AND ";
//		}
//		allWordTerms = allWordTerms.substring(0, allWordTerms.length()-4).strip();
//		Query luceneQuery = queryBuilder
//				.keyword()
//				.onField("plaintext")
//				.matching(allWordTerms)
//				.createQuery();
		
		
//		String defaultField = "plaintext";
//		Analyzer analyzer = new StandardAnalyzer();
//		QueryParser queryParser = new QueryParser()
//				.AndQuery()
//				.;
//		queryParser.setDefaultOperator(QueryParser.Operator.AND);
//		Query query = queryParser.parse(terms);

		// wrap Lucene query in org.hibernate.search.jpa.FullTextQuery (partially to make use of projections)
		org.hibernate.search.jpa.FullTextQuery jpaQuery =
			fullTextEntityManager.createFullTextQuery(luceneQuery, DocumentText.class);
		
		// project only IDs in order to reduce RAM usage (heap outgrows max memory if we pull the full DocumentText list in)
		// we can't directly pull the EISDoc field here with projection because it isn't indexed by Lucene
		jpaQuery.setProjection(ProjectionConstants.ID);

		jpaQuery.setMaxResults(limit);
		jpaQuery.setFirstResult(offset);
		
		ArrayList<Long> new_ids = new ArrayList<Long>();
		
		List<Object[]> ids = jpaQuery.getResultList();
		for(Object[] id : ids) {
			new_ids.add((Long) id[0]);
		}
		
		// use the foreign key list from Lucene to make a normal query to get all associated metadata tuples from DocumentText
		// Note: Need distinct here because multiple files inside of archives are associated with the same metadata tuples
		// TODO: Can get filenames also, display those on frontend and no longer need DISTINCT (would require a new POJO, different structure than List<EISDoc>
		// or just use metadatawithcontext with blank highlight strings as very mild overhead)
		// Alternative: Because title and therefore eisdoc ID is indexed by Lucene, we could simplify
		// the above section to projecting EISDoc IDs directly and save the second query
		javax.persistence.Query query = em.createQuery("SELECT DISTINCT doc.eisdoc FROM DocumentText doc WHERE doc.id IN :ids");
		query.setParameter("ids", new_ids);

		List<EISDoc> docs = query.getResultList();

		fullTextEntityManager.close(); // Because this is created on demand, close it when we're done
		
		return docs;
	}
	
	/** Return all records matching terms in "title" field
	 * @throws ParseException 
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<EISDoc> searchTitles(String terms) throws ParseException {
		
		String newTerms = mutateTermModifiers(terms);
		
		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em); // Create fulltext entity manager
			
		QueryParser qp = new QueryParser("title", new StandardAnalyzer());
		qp.setDefaultOperator(Operator.AND);

		// this may throw a ParseException which the caller has to deal with
		Query luceneQuery = qp.parse(newTerms);
		
		
		// wrap Lucene query in org.hibernate.search.jpa.FullTextQuery (partially to make use of projections)
		org.hibernate.search.jpa.FullTextQuery jpaQuery =
			fullTextEntityManager.createFullTextQuery(luceneQuery, EISDoc.class);
		
		jpaQuery.setMaxResults(1000000);
		jpaQuery.setFirstResult(0);
		
		List<EISDoc> docs = jpaQuery.getResultList();

		fullTextEntityManager.close(); // Because this is created on demand, close it when we're done
		
		return docs;
	}

	// Note: Probably unnecessary function
	/** Return all highlights with context for matching terms (term phrase?) */
//	@SuppressWarnings("unchecked")
//	@Override
//	public List<String> searchContext(String terms, int limit, int offset) {
//
//		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);
//		
//		QueryBuilder queryBuilder = fullTextEntityManager.getSearchFactory()
//				.buildQueryBuilder().forEntity(DocumentText.class).get();
//		Query luceneQuery = queryBuilder
//				.keyword()
//				.onFields("plaintext")
//				.matching(terms)
//				.createQuery();
//		
//		// wrap Lucene query in a javax.persistence.Query
//		javax.persistence.Query jpaQuery =
//				fullTextEntityManager.createFullTextQuery(luceneQuery, DocumentText.class);
//		
//		jpaQuery.setMaxResults(limit);
//		jpaQuery.setFirstResult(offset);
//		
//		// execute search
//		List<DocumentText> docList = jpaQuery.getResultList();
//		List<String> highlightList = new ArrayList<String>();
//		
//		// Use PhraseQuery or TermQuery to get results for matching records
//		for (DocumentText doc: docList) {
//			try {
//				String[] words = terms.split(" ");
//				if(words.length>1) {
//					highlightList.add(getHighlightPhrase(doc.getPlaintext(), words));
//				} else {
//					highlightList.add(getHighlightTerm(doc.getPlaintext(), terms));
//				}
//			} catch (IOException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			} finally {
//				fullTextEntityManager.close();
//			}
//		}
//		
//		return highlightList;
//	}
	
	/** Return all highlights with context and document ID for matching terms from "plaintext" field
	 * @throws ParseException */
//	@SuppressWarnings({ "unchecked", "deprecation" })
	@Override
	public List<MetadataWithContext> metaContext(String terms, int limit, int offset, SearchType searchType) throws ParseException {
		long startTime = System.currentTimeMillis();
		
		terms = mutateTermModifiers(terms);
		
		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);

//		QueryBuilder queryBuilder = fullTextEntityManager.getSearchFactory()
//				.buildQueryBuilder().forEntity(DocumentText.class).get();

		QueryParser qp = new QueryParser("plaintext", new StandardAnalyzer());
		qp.setDefaultOperator(Operator.AND);
		
		// this may throw a ParseException which the caller has to deal with
		Query luceneQuery = qp.parse(terms);
		
//		boolean fuzzy = false;
//		if(fuzzy) {
//			luceneQuery = queryBuilder
//					.keyword()
//					.fuzzy()
//					.withEditDistanceUpTo(fuzzyLevel) // max: 2; default: 2; aka maximum fuzziness
//					.onField("plaintext")
//					.matching(terms)
//					.createQuery();
			
//		} else {
			// for phrases
//			luceneQuery = queryBuilder
//					.phrase()
//						.withSlop(0) // default: 0 (note: doesn't work as expected)
//					.onField("plaintext")
//					.sentence(terms)
//					.createQuery();
			
			// all-word (newest querybuilder logic)
//			luceneQuery = queryBuilder
//					.simpleQueryString()
//					.onField("plaintext")
//					.withAndAsDefaultOperator()
//					.matching(terms)
//					.createQuery();
			
//			String[] termsArray = org.apache.commons.lang3.StringUtils.normalizeSpace(terms).split(" ");
//			String allWordTerms = "";
//			for(int i = 0; i < termsArray.length; i++) {
//				allWordTerms += "+" + termsArray[i] + " ";
//			}
//			allWordTerms = allWordTerms.strip();
//			
//			luceneQuery = queryBuilder
//					.keyword()
//					.onField("plaintext")
//					.matching(allWordTerms)
//					.createQuery();
//		}
			
		// wrap Lucene query in a javax.persistence.Query
		// TODO: Test org.hibernate.search.jpa.FullTextQuery instead
//		org.hibernate.search.jpa.FullTextQuery jpaQuery =
		javax.persistence.Query jpaQuery =
		fullTextEntityManager.createFullTextQuery(luceneQuery, DocumentText.class);
		
		jpaQuery.setMaxResults(limit);
		jpaQuery.setFirstResult(offset);
		
		// execute search
		List<DocumentText> docList = jpaQuery.getResultList();
		List<MetadataWithContext> highlightList = new ArrayList<MetadataWithContext>();

		QueryScorer scorer = new QueryScorer(luceneQuery);

		// Logic for exact phrase vs. all-word query
//		String[] words = terms.split(" ");
//		if(searchType == SearchType.ALL) { // .equals uses == internally
//			if(fuzzy) {
				// Fuzzy search code
//				FuzzyLikeThisQuery fuzzyQuery = new FuzzyLikeThisQuery(32, new StandardAnalyzer());
//				fuzzyQuery.addTerms(terms, "f", fuzzyLevel, 0);
//				scorer = new QueryScorer(fuzzyQuery);
//			} else {
				// Old search code: any-word
//				List<Term> termWords = new ArrayList<Term>();
//				for (String word: words) {
//					termWords.add(new Term("f", word));
//				}
//				TermsQuery query = new TermsQuery(termWords);
//				scorer = new QueryScorer(query);
				
				// all-word
//				BooleanQuery bq = new BooleanQuery();
//				for (String word: words) {
//					bq.add(new TermQuery(new Term("f", word)), Occur.MUST);
//				}
//				scorer = new QueryScorer(bq);
				
				// all-word using exact same query logic
//				scorer = new QueryScorer(luceneQuery);
//			}
//		} else {
			// Oldest code (most precision required)
//			PhraseQuery query = new PhraseQuery("f", words);
//			scorer = new QueryScorer(query);
//		}

		Highlighter highlighter = new Highlighter(globalFormatter, scorer);
		Fragmenter fragmenter = new SimpleFragmenter(fragmentSize);
		highlighter.setTextFragmenter(fragmenter);
		highlighter.setMaxDocCharsToAnalyze(Integer.MAX_VALUE);
		
		
		for (DocumentText doc: docList) {
			try {
				if(Globals.TESTING) {
					String highlight = getCustomSizeHighlightString(doc.getPlaintext(), scorer, bigFragmentSize, numberOfFragmentsMin);
					if(highlight.length() > 0) { // Length 0 shouldn't be possible since we are working on matching results already
						highlightList.add(new MetadataWithContext(doc.getEisdoc(), highlight, doc.getFilename()));
					}
				} else {
					String highlight = getHighlightString(doc.getPlaintext(), highlighter);
					if(highlight.length() > 0) { // Length 0 shouldn't be possible since we are working on matching results already
						highlightList.add(new MetadataWithContext(doc.getEisdoc(), highlight, doc.getFilename()));
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			} finally {
				fullTextEntityManager.close();
			}
		}
		
		if(Globals.TESTING) {
			long stopTime = System.currentTimeMillis();
			long elapsedTime = stopTime - startTime;
			System.out.println(elapsedTime);
		}
		
		return highlightList;
	}

		
	/** Given multi-word search term and document text, return highlights with context via getHighlightString() */
//	private static String getHighlightPhrase(String text, String[] keywords, Highlighter highlighter) throws IOException {
//	//		Builder queryBuilder = new PhraseQuery.Builder();
//	//		for (String word: words) {
//	//			queryBuilder.add(new Term("f",word));
//	//		}
//		PhraseQuery query = new PhraseQuery("f", keywords);
//		QueryScorer scorer = new QueryScorer(query);
//		
//		return getHighlightString(text, scorer);
//	}

	/** Given single-word search term and document text, return highlights with context via getHighlightString() */
//	private static String getHighlightTerm (String text, String keyword, Highlighter highlighter) throws IOException {
//		TermQuery query = new TermQuery(new Term("f", keyword));
//		QueryScorer scorer = new QueryScorer(query);
//
//
//		return getHighlightString(text, scorer);
//	}


	/** Given document text and QueryScorer, return highlights with context */
//	private static String getHighlightString (String text, QueryScorer scorer) throws IOException {
//		
//		SimpleHTMLFormatter formatter = new SimpleHTMLFormatter("<span class=\"highlight\">","</span>");
//		Highlighter highlighter = new Highlighter(formatter, scorer);
//		Fragmenter fragmenter = new SimpleFragmenter(fragmentSize);
//		highlighter.setTextFragmenter(fragmenter);
//		highlighter.setMaxDocCharsToAnalyze(text.length());
//		StandardAnalyzer stndrdAnalyzer = new StandardAnalyzer();
//		TokenStream tokenStream = stndrdAnalyzer.tokenStream("f", new StringReader(text));
//		String result = "";
//		
//		try {
//			// Add ellipses to denote that these are text fragments within the string
//			result = highlighter.getBestFragments(tokenStream, text, numberOfFragmentsMax, " ...</span><br /><span class=\"fragment\">... ");
////			System.out.println(result);
//			if(result.length()>0) {
//				result = "<span class=\"fragment\">... " + (result.replaceAll("\\n+", " ")).trim().concat(" ...</span>");
////				System.out.println(result);
//			}
//		} catch (InvalidTokenOffsetsException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} finally {
//			stndrdAnalyzer.close();
//			tokenStream.close();
//			text = "";
//		}
//	
////			StringBuilder writer = new StringBuilder("");
////			writer.append("<html>");
////			writer.append("<style>\n" +
////				".highlight {\n" +
////				" background: yellow;\n" +
////				"}\n" +
////				"</style>");
////			writer.append("<body>");
////			writer.append("");
////			writer.append("</body></html>");
//	
////			return ( writer.toString() );
//		return result;
//	 }
	

	// Given text, fragment size, num fragments, queryscorer, return highlight(s)
	private static String getCustomSizeHighlightString (String text, QueryScorer scorer, int fragmentSize, int numberOfFragments) throws IOException {
		

		Highlighter highlighter = new Highlighter(globalFormatter, scorer);
		Fragmenter fragmenter = new SimpleFragmenter(fragmentSize);
		highlighter.setTextFragmenter(fragmenter);
		highlighter.setMaxDocCharsToAnalyze(Integer.MAX_VALUE);
		StandardAnalyzer stndrdAnalyzer = new StandardAnalyzer();
		TokenStream tokenStream = stndrdAnalyzer.tokenStream("plaintext", new StringReader(text));
		String result = "";
		
		try {
			// Add ellipses to denote that these are text fragments within the string
			result = highlighter.getBestFragments(tokenStream, text, numberOfFragments, " ...</span><br /><span class=\"fragment\">... ");
//			System.out.println(result);
			if(result.length()>0) {
				result = "<span class=\"fragment\">... " + org.apache.commons.lang3.StringUtils.normalizeSpace(result).strip().concat(" ...</span>");
//				System.out.println(result);
			}
		} catch (InvalidTokenOffsetsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			stndrdAnalyzer.close();
			tokenStream.close();
			text = "";
		}
		
		return result;
	 }
	
	// Given text and highlighter, return highlights (fragments) for text
	private static String getHighlightString (String text, Highlighter highlighter) throws IOException {
		
		StandardAnalyzer stndrdAnalyzer = new StandardAnalyzer();
		TokenStream tokenStream = stndrdAnalyzer.tokenStream("plaintext", new StringReader(text));
		String result = "";
		
		try {
			// Add ellipses to denote that these are text fragments within the string
			result = highlighter.getBestFragments(tokenStream, text, numberOfFragmentsMax, " ...</span><span class=\"fragment\">... ");
			
			if(result.length()>0) {
				result = "<span class=\"fragment\">... " + org.apache.commons.lang3.StringUtils.normalizeSpace(result).strip().concat(" ...</span>");
//				System.out.println(result);
			}
		} catch (InvalidTokenOffsetsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			stndrdAnalyzer.close();
			tokenStream.close();
			text = "";
		}
	
//			StringBuilder writer = new StringBuilder("");
//			writer.append("<html>");
//			writer.append("<style>\n" +
//				".highlight {\n" +
//				" background: yellow;\n" +
//				"}\n" +
//				"</style>");
//			writer.append("<body>");
//			writer.append("");
//			writer.append("</body></html>");
	
//			return ( writer.toString() );
		return result;
	 }
	
	
	@Override
	public boolean sync() {
		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);
		try {
			fullTextEntityManager.createIndexer().startAndWait();
			return true;
		} catch (InterruptedException e) {
			// TODO log interruption?
			e.printStackTrace();
			return false;
		}
	}
	
// As long as we use the ORM to delete DocumentText records, Lucene will know about it and delete them from its index
//	public boolean delete(Long id) {
//		return true;
//	}
	
	// escapeSpecialCharacters is now useless as we analyze/parse search terms more intelligently.
	/** Escape what Lucene defines as special characters to prevent things like unintentionally excluding the word "green" 
	 * 	when searching for "Duwamish-Green".  At the same time, Lucene does not index characters like "-", so prevent
	 *  searching for "Duwamish-Green" at all and instead search for "duwamish green".  This could change if a different 
	 *  analyzer is used.  */
//	private String escapeSpecialCharacters(String inputString) {
//		
//		// Lucene supports case-sensitive inpput, but I'm indexing only lowercase words and no punctuation
//		inputString = inputString.toLowerCase();
//		//+ - && || ! ( ) { } [ ] ^ \" ~ * ? : \\ /
////		final String[] metaCharacters = {"+","-","&&","||","!","(",")","{","}","[","]","^","\"","~","*","?",":","/","  "};
//		// - allows searching for exclusions, " allows exact phrase search, * allows wildcard search...
//		final String[] metaCharacters = {"+","&&","||","!","(",")","{","}","[","]","^","~","?",":","/","  "};
//		
//		for (int i = 0 ; i < metaCharacters.length ; i++){
//			if(inputString.contains(metaCharacters[i])){
//				// Lucene can use special characters, but until we decide how to handle that power just remove them all
////				inputString = inputString.replace(metaCharacters[i],"\\"+metaCharacters[i]);
//				inputString = inputString.replace(metaCharacters[i]," ") // replace special characters with spaces
//						.trim(); // extra spaces may mean no results when looking for an exact phrase
//			}
//		}
//		return inputString;
//	}

	/** Returns search terms after enforcing two rules:  Proximity matching was limited to 1 billion, just under absolute upper limit 
	 * (when going beyond the limit, proximity matching stopped working at all).  
	 * Support for | is added by converting to ||. */
    private String mutateTermModifiers(String terms){
    	if(terms != null && terms.strip().length() > 0) {
    		// + and - must immediately precede the next term (no space), therefore don't add a space after those when replacing
    		return org.apache.commons.lang3.StringUtils.normalizeSpace(terms).replace(" | ",  " || ")
//    				.replace("and", "AND") // support for AND is implicit currently
//    				.replace("or", "OR") // Lowercase term modifiers could easily trip people up accidentally
//    				.replace("not", "NOT")
//    				.replace("&", "AND")
//    				.replace("!", "*")
//    				.replace("%", "-")
//    				.replace("/", "~") // westlaw? options, can also add confusion
    				.strip(); // QueryParser doesn't support |, does support ?, OR, NOT
//    				.replaceAll("(~\\d{10}\\d*)", "~999999999"); // this was necessary with QueryBuilder (broke after limit)
    	} else {
    		return "";
    	}
    }

	
	/**1. Triggered, verified Lucene indexing on Title (Added @Indexed for EISDoc and @Field for title)
	 * 2. Lucene-friendly Hibernate/JPA-wrapped query based on custom, dynamically created query
	 * */
    /** Title-only search */
	@Override
	public List<EISDoc> metadataSearch(SearchInputs searchInputs, int limit, int offset, SearchType searchType) {
		try {
			
			searchInputs.title = mutateTermModifiers(searchInputs.title);
			
			// Init parameter lists
			ArrayList<String> inputList = new ArrayList<String>();
			ArrayList<String> whereList = new ArrayList<String>();

//			ArrayList<Long> new_ids = new ArrayList<Long>();
			
//			boolean saneTitle = false;
			
			// TODO: if searchInputs isn't null but title is null or blank, we can return a simple query with no text searching
//			if(searchInputs != null && searchInputs.title != null && !searchInputs.title.isBlank()) {
//				String formattedTitle = org.apache.commons.lang3.StringUtils.normalizeSpace(searchInputs.title.strip());
//
//				FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);
//
//				QueryBuilder queryBuilder = fullTextEntityManager.getSearchFactory()
//						.buildQueryBuilder().forEntity(EISDoc.class).get();
//				
//				String[] arrKeywords = formattedTitle.split(" ");
//				
//				List<Query> queryList = new LinkedList<Query>();
//		        Query query = null;
//
//		        for (String keyword : arrKeywords) {
//		            query = queryBuilder.keyword().onField("title").matching(keyword).createQuery();
//		            queryList.add(query);
//		        }
//
//		        BooleanQuery finalQuery = new BooleanQuery();
//		        for (Query q : queryList) {
//		            finalQuery.add(q, Occur.MUST);
//		        }
//
//				org.hibernate.search.jpa.FullTextQuery jpaQuery =
//						fullTextEntityManager.createFullTextQuery(finalQuery, EISDoc.class);
//		        
//				
////				Query luceneQuery = queryBuilder
////						.keyword()
////						.onField("title")
//////						.withAndAsDefaultOperator()
////						.matching(formattedTitle)
////						.createQuery();
//
//				// wrap Lucene query in org.hibernate.search.jpa.FullTextQuery (partially to make use of projections)
////				org.hibernate.search.jpa.FullTextQuery jpaQuery =
////						fullTextEntityManager.createFullTextQuery(luceneQuery, EISDoc.class);
//				
//				// project only IDs in order to reduce RAM usage (heap outgrows max memory if we pull the full DocumentText list in)
//				// we can't directly pull the EISDoc field here with projection because it isn't indexed by Lucene
//				jpaQuery.setProjection(ProjectionConstants.ID);
//
//				jpaQuery.setMaxResults(limit);
//				jpaQuery.setFirstResult(offset);
//				
//				
//				List<Object[]> ids = jpaQuery.getResultList();
//				for(Object[] id : ids) {
//					System.out.println(id[0].toString());
//					new_ids.add((Long) id[0]);
//				}
//				
//				saneTitle = true;
//				
//				// use the foreign key list from Lucene to make a normal query to get all associated metadata tuples from DocumentText
//				// Note: Need distinct here because multiple files inside of archives are associated with the same metadata tuples
//				// TODO: Can get filenames also, display those on frontend and no longer need DISTINCT (would require a new POJO, different structure than List<EISDoc>)
////				javax.persistence.Query query = em.createQuery("SELECT DISTINCT doc.eisdoc FROM DocumentText doc WHERE doc.id IN :ids");
////				query.setParameter("ids", new_ids);
//			}
			
//			Query luceneQuery = queryBuilder
//					.simpleQueryString()
//					.onField("plaintext")
//					.withAndAsDefaultOperator()
//					.matching(searchInputs.title)
//					.createQuery();

			// wrap Lucene query in a javax.persistence.Query
//			FullTextQuery jpaQuery =
//			javax.persistence.Query jpaQuery =
//			fullTextEntityManager.createFullTextQuery(luceneQuery, DocumentText.class);
//			
//			jpaQuery.setMaxResults(limit);
//			jpaQuery.setFirstResult(offset);
			
			// TODO: Convert this to JPA like so:??
//			Collection<Professor> c =  
//				    em.createQuery("SELECT e " +
//				                   "FROM Professor e " +
//				                   "WHERE e.startDate BETWEEN :start AND :end")
//				      .setParameter("start", new Date(), TemporalType.DATE)
//				      .setParameter("end", new Date(), TemporalType.DATE)
//				      .getResultList();
			// So basically, your whereList probably has to change its inputs to :namedParam from ?, and your inputList
			// probably has to become an int position/object value pair or a string name/object value pair:
//			jpaQuery.setParameter(position, value)
//			jpaQuery.setParameter(name, value)
			// or something; have to review logic and syntax
			// depending on which variables are in play, probably need to build the parameters at the end after knowing
			// which ones to build, after the .createQuery
			// Note: Might actually be more complicated.  Maybe setHint helps?
			// If we can somehow use a native query, then we can even use the String we've already built in the original logic,
			// and as a bonus it'll actually work
			// If we can just set the Criteria a la FullTextQuery.setCriteriaQuery(Criteria critera)
			// https://docs.jboss.org/hibernate/search/5.4/api/org/hibernate/search/jpa/FullTextQuery.html
			// then I think we can do it.  This requires then building Criteria instead of a query string below.
			// Do we need a Hibernate session for Criteria? I don't have that
			// CriteriaBuilder is the absolute worst thing, so we'll do our best to avoid that.
			// Next solution to investigate is using the lucene queryparser to build the query from custom params.
			// https://lucene.apache.org/core/4_8_0/queryparser/org/apache/lucene/queryparser/classic/package-summary.html#package_description
			// https://stackoverflow.com/questions/60205647/how-to-construct-a-lucene-search-query-with-multiple-parameters

//			List<Predicate> predicates = new ArrayList<Predicate>();
//			List<SimpleExpression> expressionList = new ArrayList<SimpleExpression>();
//			List<Criterion> expressionList = new ArrayList<Criterion>();

//			CriteriaBuilder cb = fullTextEntityManager.getCriteriaBuilder();
			
//			CriteriaQuery q = cb.createQuery(EISDoc.class);
//			Root<EISDoc> root = q.from(EISDoc.class);
//			q.select(root);
//			
//			ParameterExpression<Integer> p = cb.parameter(Integer.class);
//			ParameterExpression<Integer> a = cb.parameter(Integer.class);
//			q.where(
//			    cb.ge(root.get("population"), p),
//			    cb.le(root.get("area"), a)
//			);

//			StandardAnalyzer stndrdAnalyzer = new StandardAnalyzer();
//			QueryParser luceneQueryParser = new QueryParser("plaintext", stndrdAnalyzer);
			
			// Select tables, columns
			String sQuery = "SELECT * FROM eisdoc";
			
			// If we have a valid title then search on new_ids
			// If we don't have a valid title then ignore new_ids and therefore run on entire database
//			if(saneTitle) {
//				if(new_ids.isEmpty()) {
//					// if valid title and new_ids is empty we can just return an empty list immediately
//					return new ArrayList<EISDoc>();
//				}
//				StringBuilder query = new StringBuilder(" id IN (");
//				for (int i = 0; i < new_ids.size(); i++) {
//					if (i > 0) {
//						query.append(",");
//					}
//					query.append("?");
//				}
//				query.append(")");
//	
//				for (int i = 0; i < new_ids.size(); i++) {
//					inputList.add(new_ids.get(i).toString());
//				}
//				whereList.add(query.toString());
//			}
			
			// Populate lists
			if(Globals.saneInput(searchInputs.startPublish)) {
				// I think this is right?
//				criteria.add(Restrictions.ge("register_date", searchInputs.startPublish));
//				q.select(root).where(cb.ge(root.get("register_date"), searchInputs.startPublish));
//				predicates.add(cb.ge(root.get("register_date"), searchInputs.startPublish));
//				expressionList.add(Restrictions.ge("register_date", searchInputs.startPublish));
				inputList.add(searchInputs.startPublish);
				whereList.add(" ((register_date) >= ?)");
			}
			
			if(Globals.saneInput(searchInputs.endPublish)) {
//				criteria.add(Restrictions.le("register_date", searchInputs.endPublish));
				inputList.add(searchInputs.endPublish);
				whereList.add(" ((register_date) <= ?)");
			}
	
			if(Globals.saneInput(searchInputs.startComment)) {
				inputList.add(searchInputs.startComment);
				whereList.add(" ((comment_date) >= ?)");
			}
			
			if(Globals.saneInput(searchInputs.endComment)) {
				inputList.add(searchInputs.endComment);
				whereList.add(" ((comment_date) <= ?)");
			}
			
			if(Globals.saneInput(searchInputs.typeAll)) { 
				// do nothing
			} else {
				
				ArrayList<String> typesList = new ArrayList<>();
				StringBuilder query = new StringBuilder(" document_type IN (");
				if(Globals.saneInput(searchInputs.typeFinal)) {
					typesList.add("Final");
				}
	
				if(Globals.saneInput(searchInputs.typeDraft)) {
					typesList.add("Draft");
				}
				
				if(Globals.saneInput(searchInputs.typeOther)) {
					typesList.addAll(Globals.EIS_TYPES);
				}
				String[] docTypes = typesList.toArray(new String[0]);
				for (int i = 0; i < docTypes.length; i++) {
					if (i > 0) {
						query.append(",");
					}
					query.append("?");
				}
				query.append(")");
	
				for (int i = 0; i < docTypes.length; i++) {
					inputList.add(docTypes[i]);
				}
				
				if(docTypes.length>0) {
					whereList.add(query.toString());
				}
	
			}
	
			// TODO: Temporary logic, filenames should each have their own field in the database later 
			// and they may also be a different format
			// (this will eliminate the need for the _% LIKE logic also)
			// _ matches exactly one character and % matches zero to many, so _% matches at least one arbitrary character
			if(Globals.saneInput(searchInputs.needsComments)) {
	//			whereList.add(" (documents LIKE 'CommentLetters-_%' OR documents LIKE 'EisDocuments-_%;CommentLetters-_%')");
				whereList.add(" (comments_filename<>'')");
			}
	
			if(Globals.saneInput(searchInputs.needsDocument)) { // Don't need an input for this right now
	//			whereList.add(" (documents LIKE 'EisDocuments-_%' OR documents LIKE 'EisDocuments-_%;CommentLetters-_%')");
				whereList.add(" (filename<>'')");
			}
			
			if(Globals.saneInput(searchInputs.state)) {
				StringBuilder query = new StringBuilder(" state IN (");
				for (int i = 0; i < searchInputs.state.length; i++) {
					if (i > 0) {
						query.append(",");
					}
					query.append("?");
				}
				query.append(")");
	
				for (int i = 0; i < searchInputs.state.length; i++) {
					inputList.add(searchInputs.state[i]);
				}
				whereList.add(query.toString());
			}
	
			if(Globals.saneInput(searchInputs.agency)) {
				StringBuilder query = new StringBuilder(" agency IN (");
				for (int i = 0; i < searchInputs.agency.length; i++) {
					if (i > 0) {
						query.append(",");
					}
					query.append("?");
				}
				query.append(")");
	
				for (int i = 0; i < searchInputs.agency.length; i++) {
					inputList.add(searchInputs.agency[i]);
				}
				whereList.add(query.toString());
			}
			
			boolean addAnd = false;
			for (String i : whereList) {
				if(addAnd) { // Not first conditional, append AND
					sQuery += " AND";
				} else { // First conditional, append WHERE
					sQuery += " WHERE";
				}
				sQuery += i; // Append conditional
				
				addAnd = true; // Raise AND flag for future iterations
			}
			
			// Order by Lucene score, not title, also we need a way to order the title results first for one of the A|B tests
//			sQuery += " ORDER BY title";
			
			
			// This is unfortunately the only way to preserve Lucene's order
//			if(saneTitle) {
//				StringBuilder query = new StringBuilder(" ORDER BY FIELD(id, ");
//				for (int i = 0; i < new_ids.size(); i++) {
//					if (i > 0) {
//						query.append(",");
//					}
//					query.append("?");
//				}
//				query.append(")");
//	
//				for (int i = 0; i < new_ids.size(); i++) {
//					inputList.add(new_ids.get(i).toString());
//				}
//				whereList.add(query.toString());
//			}
			
			
			// Finalize query
			
			// No reason to limit metadata-only search
			int queryLimit = 1000000;
			
			sQuery += " LIMIT " + String.valueOf(queryLimit);

//			jpaQuery.setCriteriaQuery(criteria);

			// TODO: Is this usable?
//			org.apache.lucene.search.Query finalQuery = luceneQueryParser.parse(sQuery);
			
//			javax.persistence.Query query = em.createQuery("SELECT DISTINCT doc.eisdoc FROM DocumentText doc WHERE doc.id IN :ids");
			// Finalize query
//			javax.persistence.Query finalQuery = em.createQuery(sQuery);
//			finalQuery.setMaxResults(limit);
//			finalQuery.setFirstResult(offset);
			
			// execute search
//			List<EISDoc> docList = finalQuery.getResultList();
			
			
			
			// Run query
			List<EISDoc> records = jdbcTemplate.query
			(
				sQuery, 
				inputList.toArray(new Object[] {}),
				(rs, rowNum) -> new EISDoc(
					rs.getLong("id"), 
					rs.getString("title"), 
					rs.getString("document_type"),
					rs.getObject("comment_date", LocalDate.class), 
					rs.getObject("register_date", LocalDate.class), 
					rs.getString("agency"),
					rs.getString("department"),
					rs.getString("cooperating_agency"),
					rs.getString("summary_text"),
					rs.getString("state"), 
					rs.getString("filename"),
					rs.getString("comments_filename"),
					rs.getString("folder"),
					rs.getLong("size"),
					rs.getString("web_link"),
					rs.getString("notes"),
					rs.getObject("noi_date", LocalDate.class), 
					rs.getObject("draft_noa", LocalDate.class), 
					rs.getObject("final_noa", LocalDate.class), 
					rs.getObject("first_rod_date", LocalDate.class)
				)
			);
			
			// debugging
			if(Globals.TESTING) {
				System.out.println(sQuery); 
			}

			// If we have a title then take the JDBC results and run a Lucene query on just them
			// (this is the simplest way to return the results in the scored order from Lucene)
			// Unfortunately, this low-level garbage breaks things like ~proximity matching and "exact phrase" searches.
			// TODO: Therefore, we have to run the lucene query on everything and manually join the results instead,
			// excluding anything that doesn't appear in BOTH result sets
//			if(searchInputs != null && searchInputs.title != null && !searchInputs.title.isBlank()) {
//				String formattedTitle = org.apache.commons.lang3.StringUtils.normalizeSpace(searchInputs.title.strip());
//
//				FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);
//
//				QueryBuilder queryBuilder = fullTextEntityManager.getSearchFactory()
//						.buildQueryBuilder().forEntity(EISDoc.class).get();
//				
//				String[] arrKeywords = formattedTitle.split(" ");
//				
//				List<Query> queryList = new LinkedList<Query>();
//		        Query query = null;
//	
//				// Add keyword queries for each word
//		        for (String keyword : arrKeywords) {
//		            query = queryBuilder.keyword().onField("title").matching(keyword).createQuery();
//		            queryList.add(query);
//		        }
//
//		        BooleanQuery.setMaxClauseCount(200000);
//		        BooleanQuery finalQuery = new BooleanQuery();
//		        for (Query q : queryList) {
//		            finalQuery.add(q, Occur.MUST);
//		        }
//				for(EISDoc record: records) {
//		            finalQuery.add(
//		            		new TermQuery(new Term("ID", record.getId().toString())), Occur.SHOULD);
//				}
//	
//				org.hibernate.search.jpa.FullTextQuery jpaQuery =
//						fullTextEntityManager.createFullTextQuery(finalQuery, EISDoc.class);
//				
//				jpaQuery.setMaxResults(limit);
//				jpaQuery.setFirstResult(offset);
//				
//				List<EISDoc> results = jpaQuery.getResultList();
//				
//				return results;
//			} else {
//				return records;
//			}
			
			// Run Lucene query on title if we have one, join with JDBC results, return final results
			if(!searchInputs.title.isBlank()) {

				List<EISDoc> results = searchTitles(searchInputs.title);
				
				HashSet<Long> justRecordIds = new HashSet<Long>();
				for(EISDoc record: records) {
					justRecordIds.add(record.getId());
				}
				
				// Build new result list in the same order but excluding records that don't appear in the first result set (records).
				List<EISDoc> finalResults = new ArrayList<EISDoc>();
				for(EISDoc result : results) {
					if(justRecordIds.contains(result.getId())) {
						finalResults.add(result);
					}
				}
				
				if(Globals.TESTING) {
					System.out.println("Records filtered " + records.size());
					System.out.println("Records by term " + results.size());
				}
				
				return finalResults;
			} else { // no title: simply return JDBC results
				return records;
			}
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	
	}
	
	/** Uses full parameters (not just a String for terms) to narrow down results */
	private List<EISDoc> getFilteredRecords(SearchInputs searchInputs) {
		searchInputs.title = mutateTermModifiers(searchInputs.title);
		
		ArrayList<String> inputList = new ArrayList<String>();
		ArrayList<String> whereList = new ArrayList<String>();

		// Select tables, columns
		String sQuery = "SELECT * FROM eisdoc";
		
		// Populate lists
		if(Globals.saneInput(searchInputs.startPublish)) {
			inputList.add(searchInputs.startPublish);
			whereList.add(" ((register_date) >= ?)");
		}
		
		if(Globals.saneInput(searchInputs.endPublish)) {
			inputList.add(searchInputs.endPublish);
			whereList.add(" ((register_date) <= ?)");
		}

		if(Globals.saneInput(searchInputs.startComment)) {
			inputList.add(searchInputs.startComment);
			whereList.add(" ((comment_date) >= ?)");
		}
		
		if(Globals.saneInput(searchInputs.endComment)) {
			inputList.add(searchInputs.endComment);
			whereList.add(" ((comment_date) <= ?)");
		}
		
		if(Globals.saneInput(searchInputs.typeAll)) { 
			// do nothing
		} else {
			
			ArrayList<String> typesList = new ArrayList<>();
			StringBuilder query = new StringBuilder(" document_type IN (");
			if(Globals.saneInput(searchInputs.typeFinal)) {
				typesList.add("Final");
			}

			if(Globals.saneInput(searchInputs.typeDraft)) {
				typesList.add("Draft");
			}
			
			if(Globals.saneInput(searchInputs.typeOther)) {
				typesList.addAll(Globals.EIS_TYPES);
			}
			String[] docTypes = typesList.toArray(new String[0]);
			for (int i = 0; i < docTypes.length; i++) {
				if (i > 0) {
					query.append(",");
				}
				query.append("?");
			}
			query.append(")");

			for (int i = 0; i < docTypes.length; i++) {
				inputList.add(docTypes[i]);
			}
			
			if(docTypes.length>0) {
				whereList.add(query.toString());
			}

		}

		if(Globals.saneInput(searchInputs.needsComments)) { // Don't need an input for this right now
			whereList.add(" (comments_filename<>'')");
		}

		if(Globals.saneInput(searchInputs.needsDocument)) { // Don't need an input for this right now
			whereList.add(" (filename<>'')");
		}
		
		if(Globals.saneInput(searchInputs.state)) {
			StringBuilder query = new StringBuilder(" state IN (");
			for (int i = 0; i < searchInputs.state.length; i++) {
				if (i > 0) {
					query.append(",");
				}
				query.append("?");
			}
			query.append(")");

			for (int i = 0; i < searchInputs.state.length; i++) {
				inputList.add(searchInputs.state[i]);
			}
			whereList.add(query.toString());
		}

		if(Globals.saneInput(searchInputs.agency)) {
			StringBuilder query = new StringBuilder(" agency IN (");
			for (int i = 0; i < searchInputs.agency.length; i++) {
				if (i > 0) {
					query.append(",");
				}
				query.append("?");
			}
			query.append(")");

			for (int i = 0; i < searchInputs.agency.length; i++) {
				inputList.add(searchInputs.agency[i]);
			}
			whereList.add(query.toString());
		}
		
		boolean addAnd = false;
		for (String i : whereList) {
			if(addAnd) { // Not first conditional, append AND
				sQuery += " AND";
			} else { // First conditional, append WHERE
				sQuery += " WHERE";
			}
			sQuery += i; // Append conditional
			
			addAnd = true; // Raise AND flag for future iterations
		}
		
		
		// Finalize query
		int queryLimit = 1000000;

		// Note: For the metadata results, query is very fast and since we use this dataset for a join/comparison later
		// we do not want to limit it (for now, 1 million is fine)
//		if(Globals.saneInput(searchInputs.limit)) {
//			if(searchInputs.limit <= 100000) {
//				queryLimit = searchInputs.limit;
//			}
//		}
		
		
		sQuery += " LIMIT " + String.valueOf(queryLimit);

		// Run query
		List<EISDoc> records = jdbcTemplate.query
		(
			sQuery, 
			inputList.toArray(new Object[] {}),
			(rs, rowNum) -> new EISDoc(
				rs.getLong("id"), 
				rs.getString("title"), 
				rs.getString("document_type"),
				rs.getObject("comment_date", LocalDate.class), 
				rs.getObject("register_date", LocalDate.class), 
				rs.getString("agency"),
				rs.getString("department"),
				rs.getString("cooperating_agency"),
				rs.getString("summary_text"),
				rs.getString("state"), 
				rs.getString("filename"),
				rs.getString("comments_filename"),
				rs.getString("folder"),
				rs.getLong("size"),
				rs.getString("web_link"),
				rs.getString("notes"),
				rs.getObject("noi_date", LocalDate.class), 
				rs.getObject("draft_noa", LocalDate.class), 
				rs.getObject("final_noa", LocalDate.class), 
				rs.getObject("first_rod_date", LocalDate.class)
			)
		);

		// debugging
		if(Globals.TESTING) {
//			if(searchInputs.endPublish != null) {
//				DateTimeFormatter dateFormatter = DateTimeFormatter.ISO_DATE_TIME;
//				DateValidator validator = new DateValidatorUsingLocalDate(dateFormatter);
//				System.out.println(validator.isValid(searchInputs.endPublish));
//				System.out.println(searchInputs.endPublish);
//			}
//			System.out.println(sQuery); 
//			System.out.println(searchInputs.title);
		}
		
		return records;
	}
	
	// objective: Search both fields at once and return quickly in combined scored order
	@Override
	public List<Object[]> getRaw(String terms) throws ParseException {
		long startTime = System.currentTimeMillis();
		
		// Normalize whitespace and support added term modifiers
	    String formattedTerms = org.apache.commons.lang3.StringUtils.normalizeSpace(mutateTermModifiers(terms).strip());

	    if(Globals.TESTING) {System.out.println("Search terms: " + formattedTerms);}
	    
		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);

		// Lucene flattens (denormalizes) and so searching both tables at once is simple enough, 
		// but the results will contain both types mixed together
		MultiFieldQueryParser mfqp = new MultiFieldQueryParser(
					new String[] {"title", "plaintext"},
					new StandardAnalyzer());
		mfqp.setDefaultOperator(Operator.AND);

		Query luceneQuery = mfqp.parse(formattedTerms);
		
		org.hibernate.search.jpa.FullTextQuery jpaQuery =
					fullTextEntityManager.createFullTextQuery(luceneQuery);

		// Ex: [[8383,"nepaBackend.model.EISDoc",0.8749341],[1412,"nepaBackend.model.DocumentText",0.20437382]]
		jpaQuery.setProjection(
					ProjectionConstants.ID
					,ProjectionConstants.OBJECT_CLASS
					,ProjectionConstants.SCORE
					);
		jpaQuery.setMaxResults(1000000);
		jpaQuery.setFirstResult(0);
		
		List<Object[]> results = jpaQuery.getResultList();

		if(Globals.TESTING) {
			System.out.println("Results #: " + results.size());
			
			long stopTime = System.currentTimeMillis();
			long elapsedTime = stopTime - startTime;
			System.out.println("Time elapsed: " + elapsedTime);
		}
		
		return results;
	}

	// objective: Search both fields at once and return quickly in combined scored order
	@Override
	public List<MetadataWithContext2> getScored(String terms) throws ParseException {
		long startTime = System.currentTimeMillis();

		// Normalize whitespace and support added term modifiers
	    String formattedTerms = org.apache.commons.lang3.StringUtils.normalizeSpace(mutateTermModifiers(terms).strip());

	    if(Globals.TESTING) {System.out.println("Search terms: " + formattedTerms);}
	    
		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);

		// Lucene flattens (denormalizes) and so searching both tables at once is simple enough, 
		// but the results will contain both types mixed together
		MultiFieldQueryParser mfqp = new MultiFieldQueryParser(
					new String[] {"title", "plaintext"},
					new StandardAnalyzer());
		mfqp.setDefaultOperator(Operator.AND);

		Query luceneQuery = mfqp.parse(formattedTerms);
		
		org.hibernate.search.jpa.FullTextQuery jpaQuery =
				fullTextEntityManager.createFullTextQuery(luceneQuery);

		// Ex: [[8383,"nepaBackend.model.EISDoc",0.8749341],[1412,"nepaBackend.model.DocumentText",0.20437382]]
		jpaQuery.setProjection(
				ProjectionConstants.ID
				,ProjectionConstants.OBJECT_CLASS
				,ProjectionConstants.SCORE
				);
		jpaQuery.setMaxResults(1000000);
		jpaQuery.setFirstResult(0);
		
		// Lazy fetching isn't so easy here with combined results, so the goal is to get the order
		// first and then get all of the results maintaining that order but without getting full
		// texts which is slow and also overflows the heap
		
		// Could potentially try to get ProjectionConstants.ID and ProjectionConstants.SCORE
		// for two separate searches, join and sort by score,
		// then get the metadata and filenames.  This would maintain the order.
		
		// Returns a list containing both EISDoc and DocumentText objects.
		List<Object[]> results = jpaQuery.getResultList();
		
		if(Globals.TESTING) {System.out.println("Initial results size: " + results.size());}
		
		List<ScoredResult> converted = new ArrayList<ScoredResult>();
		Set<Long> metaIds = new HashSet<Long>();
		Set<Long> textIds = new HashSet<Long>();
		
		int i = 0;
		
		for(Object[] result : results) {
			ScoredResult convert = new ScoredResult();
			convert.id = (Long) result[0];
			convert.className = (Class<?>) result[1];
			convert.score = (Float) result[2];
			convert.idx = i;
			if(convert.className.equals(EISDoc.class)) {
				metaIds.add(convert.id);
			} else {
				textIds.add(convert.id);
			}
			converted.add(convert);
			i++;
		}
		
		// [8383,"nepaBackend.model.EISDoc"]
		// ProjectionConstants.SCORE could also give score to sort by.
		
		// 1: Get EISDocs by IDs.
		
		List<EISDoc> docs = em.createQuery("SELECT d FROM EISDoc d WHERE d.id IN :ids")
			.setParameter("ids", metaIds).getResultList();

		if(Globals.TESTING){System.out.println("Docs results size: " + docs.size());}
		
		HashMap<Long, EISDoc> hashDocs = new HashMap<Long, EISDoc>();
		for(EISDoc doc : docs) {
			hashDocs.put(doc.getId(), doc);
		}

		// 2: Get DocumentTexts by IDs WITHOUT getting the entire texts.

		List<Object[]> textIdMetaAndFilenames = em.createQuery("SELECT d.id, d.eisdoc, d.filename FROM DocumentText d WHERE d.id IN :ids")
				.setParameter("ids", textIds).getResultList();

		if(Globals.TESTING){System.out.println("Texts results size: " + textIdMetaAndFilenames.size());}
		
		HashMap<Long, ReducedText> hashTexts = new HashMap<Long, ReducedText>();
		for(Object[] obj : textIdMetaAndFilenames) {
			hashTexts.put(
					(Long) obj[0], 
					new ReducedText(
						(Long) obj[0],
						(EISDoc) obj[1],
						(String) obj[2]
					));
		}
		
		List <MetadataWithContext2> combinedResults = new ArrayList<MetadataWithContext2>();

		// 3: Join (combine) results from the two tables
		// 3.1: Condense (add filenames to existing records rather than adding new records)
		// 3.2: keep original order
		
		HashMap<Long, Integer> added = new HashMap<Long, Integer>();
		int position = 0;
		
		for(ScoredResult ordered : converted) {
			if(ordered.className.equals(EISDoc.class)) {
				if(!added.containsKey(ordered.id)) {
					// Add EISDoc into logical position
					combinedResults.add(new MetadataWithContext2(
							hashDocs.get(ordered.id),
							new ArrayList<String>(),
							"",
							ordered.score));
					added.put(ordered.id, position);
					position++;
				}
				// If we already have one, do nothing - (title result: no filenames to add.)
			} else {
				EISDoc eisFromDoc = hashTexts.get(ordered.id).eisdoc;
				if(!added.containsKey(eisFromDoc.getId())) {
					// Add DocumentText into logical position
					combinedResults.add(new MetadataWithContext2(
							eisFromDoc,
							new ArrayList<String>(),
							hashTexts.get(ordered.id).filename,
							ordered.score));
					added.put(eisFromDoc.getId(), position);
					position++;
				} else {
					// Add this combinedResult's filename to filename list
					String currentFilename = combinedResults.get(added.get(eisFromDoc.getId()))
							.getFilenames();
					// > is not a valid directory/filename char, so should work as delimiter
					// If currentFilename is blank (title match came first), no need to concat.  Just set.
					if(currentFilename.isBlank()) {
						combinedResults.get(added.get(eisFromDoc.getId()))
						.setFilenames(
							hashTexts.get(ordered.id).filename
						);
					} else {
						combinedResults.get(added.get(eisFromDoc.getId()))
						.setFilenames(
							currentFilename.concat(">" + hashTexts.get(ordered.id).filename)
						);
					}
				}
			}
		}
		
		if(Globals.TESTING) {
			System.out.println("Results #: " + results.size());
			
			long stopTime = System.currentTimeMillis();
			long elapsedTime = stopTime - startTime;
			System.out.println("Time elapsed: " + elapsedTime);
		}
		
		return combinedResults;
	}
	


	private List<MetadataWithContext3> getScoredFVH(String title) throws ParseException {

		// Normalize whitespace and support added term modifiers
	    String formattedTerms = org.apache.commons.lang3.StringUtils.normalizeSpace(mutateTermModifiers(title).strip());

	    if(Globals.TESTING) {System.out.println("Search terms: " + formattedTerms);}
	    
		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);

		// Lucene flattens (denormalizes) and so searching both tables at once is simple enough, 
		// but the results will contain both types mixed together
		MultiFieldQueryParser mfqp = new MultiFieldQueryParser(
					new String[] {"title", "plaintext"},
					new StandardAnalyzer());
		mfqp.setDefaultOperator(Operator.AND);

		Query luceneQuery = mfqp.parse(formattedTerms);
		
		org.hibernate.search.jpa.FullTextQuery jpaQuery =
				fullTextEntityManager.createFullTextQuery(luceneQuery);

		// Ex: [[8383,"nepaBackend.model.EISDoc",0.8749341],[1412,"nepaBackend.model.DocumentText",0.20437382]]
		jpaQuery.setProjection(
				ProjectionConstants.ID
				,ProjectionConstants.OBJECT_CLASS
				,ProjectionConstants.SCORE
				);
		jpaQuery.setMaxResults(1000000);
		jpaQuery.setFirstResult(0);
		
		// Lazy fetching isn't so easy here with combined results, so the goal is to get the order
		// first and then get all of the results maintaining that order but without getting full
		// texts which is slow and also overflows the heap
		
		// Could potentially try to get ProjectionConstants.ID and ProjectionConstants.SCORE
		// for two separate searches, join and sort by score,
		// then get the metadata and filenames.  This would maintain the order.
		
		// Returns a list containing both EISDoc and DocumentText objects.
		List<Object[]> results = jpaQuery.getResultList();
		
		if(Globals.TESTING) {System.out.println("Initial results size: " + results.size());}
		
		List<ScoredResult> converted = new ArrayList<ScoredResult>();
		Set<Long> metaIds = new HashSet<Long>();
		Set<Long> textIds = new HashSet<Long>();
		
		int i = 0;
		
		for(Object[] result : results) {
			ScoredResult convert = new ScoredResult();
			convert.id = (Long) result[0];
			convert.className = (Class<?>) result[1];
			convert.score = (Float) result[2];
			convert.idx = i;
			if(convert.className.equals(EISDoc.class)) {
				metaIds.add(convert.id);
			} else {
				textIds.add(convert.id);
			}
			converted.add(convert);
			i++;
		}
		
		// [8383,"nepaBackend.model.EISDoc"]
		// ProjectionConstants.SCORE could also give score to sort by.
		
		// 1: Get EISDocs by IDs.
		
		List<EISDoc> docs = em.createQuery("SELECT d FROM EISDoc d WHERE d.id IN :ids")
			.setParameter("ids", metaIds).getResultList();

		if(Globals.TESTING){System.out.println("Docs results size: " + docs.size());}
		
		HashMap<Long, EISDoc> hashDocs = new HashMap<Long, EISDoc>();
		for(EISDoc doc : docs) {
			hashDocs.put(doc.getId(), doc);
		}

		// 2: Get DocumentTexts by IDs WITHOUT getting the entire texts.

		List<Object[]> textIdMetaAndFilenames = em.createQuery("SELECT d.id, d.eisdoc, d.filename FROM DocumentText d WHERE d.id IN :ids")
				.setParameter("ids", textIds).getResultList();

		if(Globals.TESTING){System.out.println("Texts results size: " + textIdMetaAndFilenames.size());}
		
		HashMap<Long, ReducedText> hashTexts = new HashMap<Long, ReducedText>();
		for(Object[] obj : textIdMetaAndFilenames) {
			hashTexts.put(
					(Long) obj[0], 
					new ReducedText(
						(Long) obj[0],
						(EISDoc) obj[1],
						(String) obj[2]
					));
		}
		
		List <MetadataWithContext3> combinedResults = new ArrayList<MetadataWithContext3>();

		// 3: Join (combine) results from the two tables
		// 3.1: Condense (add filenames to existing records rather than adding new records)
		// 3.2: keep original order
		
		HashMap<Long, Integer> added = new HashMap<Long, Integer>();
		int position = 0;
		
		for(ScoredResult ordered : converted) {
			if(ordered.className.equals(EISDoc.class)) {
				if(!added.containsKey(ordered.id)) {
					// Add EISDoc into logical position
					combinedResults.add(new MetadataWithContext3(
							new ArrayList<Long>(),
							hashDocs.get(ordered.id),
							new ArrayList<String>(),
							"",
							ordered.score));
					added.put(ordered.id, position);
					position++;
				}
				// If we already have one, do nothing - (title result: no filenames to add.)
			} else {
				EISDoc eisFromDoc = hashTexts.get(ordered.id).eisdoc;
				if(!added.containsKey(eisFromDoc.getId())) {
					// Add DocumentText into logical position
					MetadataWithContext3 entry = new MetadataWithContext3(
							new ArrayList<Long>(),
							eisFromDoc,
							new ArrayList<String>(),
							hashTexts.get(ordered.id).filename,
							ordered.score);
					entry.addId(ordered.id);
					combinedResults.add(entry);
					added.put(eisFromDoc.getId(), position);
					position++;
				} else {
					// Add this combinedResult's id to id list
					combinedResults.get(added.get(eisFromDoc.getId())).addId(ordered.id);
					// Add this combinedResult's filename to filename list
					String currentFilename = combinedResults.get(added.get(eisFromDoc.getId()))
							.getFilenames();
					// > is not a valid directory/filename char, so should work as delimiter
					// If currentFilename is blank (title match came first), no need to concat.  Just set.
					if(currentFilename.isBlank()) {
						combinedResults.get(added.get(eisFromDoc.getId()))
						.setFilenames(
							hashTexts.get(ordered.id).filename
						);
					} else {
						combinedResults.get(added.get(eisFromDoc.getId()))
						.setFilenames(
							currentFilename.concat(">" + hashTexts.get(ordered.id).filename)
						);
					}
				}
			}
		}
		
		return combinedResults;
	}

	/** Combination title/fulltext query including the metadata parameters like agency/state/...
			 * and this is currently the default search; returns metadata plus filename 
			 * using Lucene's internal default scoring algorithm
			 * @throws ParseException
			 * */
	@Override
	public List<MetadataWithContext2> CombinedSearchNoContext(SearchInputs searchInputs, SearchType searchType) {
		try {
			long startTime = System.currentTimeMillis();
			
			if(Globals.TESTING) {
				System.out.println("Offset: " + searchInputs.offset);
			}
			
			List<EISDoc> records = getFilteredRecords(searchInputs);
			
			// Run Lucene query on title if we have one, join with JDBC results, return final results
			if(!searchInputs.title.isBlank()) {
				String title = searchInputs.title;

				// Collect IDs filtered by params
				HashSet<Long> justRecordIds = new HashSet<Long>();
				for(EISDoc record: records) {
					justRecordIds.add(record.getId());
				}

				List<MetadataWithContext2> results = getScored(title);
				
				// Build new result list in the same order but excluding records that don't appear in the first result set (records).
				List<MetadataWithContext2> finalResults = new ArrayList<MetadataWithContext2>();
				for(int i = 0; i < results.size(); i++) {
					if(justRecordIds.contains(results.get(i).getDoc().getId())) {
						finalResults.add(results.get(i));
					}
				}
				
				if(Globals.TESTING) {
					System.out.println("Records 1 " + records.size());
					System.out.println("Records 2 " + results.size());
				}

				if(Globals.TESTING) {
					long stopTime = System.currentTimeMillis();
					long elapsedTime = stopTime - startTime;
					System.out.println("Lucene search time: " + elapsedTime);
				}
				return results;
			} else { // no title: simply return JDBC results...  however they have to be translated
				// TODO: If we care to avoid this, frontend has to know if it's sending a title or not, and ask for the appropriate
				// return type (either EISDoc or MetadataWithContext), and then we need two versions of the search on the backend
				List<MetadataWithContext2> finalResults = new ArrayList<MetadataWithContext2>();
				for(EISDoc record : records) {
					finalResults.add(new MetadataWithContext2(record, new ArrayList<String>(), "", 0));
				}
				return finalResults;
			}
			
//			return lucenePrioritySearch(searchInputs.title, limit, offset);
		} catch(Exception e) {
			e.printStackTrace();
			String problem = e.getLocalizedMessage();
			MetadataWithContext2 result = new MetadataWithContext2(null, new ArrayList<String>(), problem, 0);
			List<MetadataWithContext2> results = new ArrayList<MetadataWithContext2>();
			results.add(result);
			return results;
		}
	}

	/** Combination title/fulltext query including the metadata parameters like agency/state/...
	 * returns metadata plus filename 
	 * using Lucene's internal default scoring algorithm
	 * @throws ParseException
	 * */
//	@Override
//	public List<MetadataWithContext2> CombinedSearchNoContextOld(SearchInputs searchInputs, SearchType searchType) {
//		try {
//			long startTime = System.currentTimeMillis();
////			System.out.println("Offset: " + searchInputs.offset);
//			List<EISDoc> records = getFilteredRecords(searchInputs);
//			
//			// Run Lucene query on title if we have one, join with JDBC results, return final results
//			if(!searchInputs.title.isBlank()) {
//				String formattedTitle = mutateTermModifiers(searchInputs.title);
//
//				HashSet<Long> justRecordIds = new HashSet<Long>();
//				for(EISDoc record: records) {
//					justRecordIds.add(record.getId());
//				}
//
//				List<MetadataWithContext2> results = searchNoContext(formattedTitle, searchInputs.limit, searchInputs.offset, justRecordIds);
//				
//				// Build new result list in the same order but excluding records that don't appear in the first result set (records).
//				List<MetadataWithContext2> finalResults = new ArrayList<MetadataWithContext2>();
//				for(int i = 0; i < results.size(); i++) {
//					if(justRecordIds.contains(results.get(i).getDoc().getId())) {
//						finalResults.add(results.get(i));
//					}
//				}
//				
//				if(Globals.TESTING) {
//					System.out.println("Records 1 " + records.size());
//					System.out.println("Records 2 " + results.size());
//				}
//
//				if(Globals.TESTING) {
//					long stopTime = System.currentTimeMillis();
//					long elapsedTime = stopTime - startTime;
//					System.out.println("Lucene search time: " + elapsedTime);
//				}
//				return finalResults;
//			} else { // no title: simply return JDBC results...  however they have to be translated
//				// TODO: If we care to avoid this, frontend has to know if it's sending a title or not, and ask for the appropriate
//				// return type (either EISDoc or MetadataWithContext), and then we need two versions of the search on the backend
//				List<MetadataWithContext2> finalResults = new ArrayList<MetadataWithContext2>();
//				for(EISDoc record : records) {
//					finalResults.add(new MetadataWithContext2(record, new ArrayList<String>(), ""));
//				}
//				return finalResults;
//			}
//			
////			return lucenePrioritySearch(searchInputs.title, limit, offset);
//		} catch(Exception e) {
//			e.printStackTrace();
//			return new ArrayList<MetadataWithContext2>();
//		}
//	}
	
	/** "A/B testing" search functions: */

	/** Combination title/fulltext query including the metadata parameters like agency/state/...
	 * and this is currently the default search; returns metadata plus filename and highlights
	 * using Lucene's internal default scoring algorithm
	 * @throws ParseException
	 * */
	@Override
	public List<MetadataWithContext> CombinedSearchLucenePriority(SearchInputs searchInputs, SearchType searchType) {
		try {
			long startTime = System.currentTimeMillis();
			if(Globals.TESTING) {System.out.println("Offset: " + searchInputs.offset);}
			List<EISDoc> records = getFilteredRecords(searchInputs);
			
			// Run Lucene query on title if we have one, join with JDBC results, return final results
			if(!searchInputs.title.isBlank()) {
				String formattedTitle = mutateTermModifiers(searchInputs.title);

				HashSet<Long> justRecordIds = new HashSet<Long>();
				for(EISDoc record: records) {
					justRecordIds.add(record.getId());
				}

				List<MetadataWithContext> results = lucenePrioritySearch(formattedTitle, searchInputs.limit, searchInputs.offset, justRecordIds);
				
				// Build new result list in the same order but excluding records that don't appear in the first result set (records).
				List<MetadataWithContext> finalResults = new ArrayList<MetadataWithContext>();
				for(int i = 0; i < results.size(); i++) {
					if(justRecordIds.contains(results.get(i).getDoc().getId())) {
						finalResults.add(results.get(i));
					}
				}
				
				if(Globals.TESTING) {
					System.out.println("Records 1 " + records.size());
					System.out.println("Records 2 " + results.size());
				}

				if(Globals.TESTING) {
					long stopTime = System.currentTimeMillis();
					long elapsedTime = stopTime - startTime;
					System.out.println("Lucene search time: " + elapsedTime);
				}
				return finalResults;
			} else { // no title: simply return JDBC results...  however they have to be translated
				// TODO: If we care to avoid this, frontend has to know if it's sending a title or not, and ask for the appropriate
				// return type (either EISDoc or MetadataWithContext), and then we need two versions of the search on the backend
				List<MetadataWithContext> finalResults = new ArrayList<MetadataWithContext>();
				for(EISDoc record : records) {
					finalResults.add(new MetadataWithContext(record, "", ""));
				}
				return finalResults;
			}
			
//			return lucenePrioritySearch(searchInputs.title, limit, offset);
		} catch(Exception e) {
			e.printStackTrace();
			return new ArrayList<MetadataWithContext>();
		}
	}
	
	public List<MetadataWithContext3> allInOne(SearchInputs searchInputs) throws IOException, ParseException {

		long startTime = System.currentTimeMillis();
		List<MetadataWithContext3> results = new ArrayList<MetadataWithContext3>();
		Path index = Path.of("./data/lucene/nepaBackend.model.DocumentText");
		IndexReader reader = null;
			reader = DirectoryReader.open(FSDirectory.open(index));

		try {
			
			List<EISDoc> records = getFilteredRecords(searchInputs);
			
			// Run Lucene query on title if we have one, join with JDBC results, return final results
			if(!searchInputs.title.isBlank()) {
				String title = searchInputs.title;

				// Collect IDs filtered by params
				HashSet<Long> justRecordIds = new HashSet<Long>();
				for(EISDoc record: records) {
					justRecordIds.add(record.getId());
				}

				results = getScoredFVH(title);
				
				// Build new result list in the same order but excluding records that don't appear in the first result set (records).
//				List<MetadataWithContext2> finalResults = new ArrayList<MetadataWithContext2>();
//				for(int i = 0; i < results.size(); i++) {
//					if(justRecordIds.contains(results.get(i).getDoc().getId())) {
//						finalResults.add(results.get(i));
//					}
//				}
			} else { // no title: simply return JDBC results...  however they have to be translated
				for(EISDoc record : records) {
					results.add(new MetadataWithContext3(new ArrayList<Long>(), record, new ArrayList<String>(), "", 0));
				}
				return results;
			}
			
		} catch(Exception e) {
			e.printStackTrace();
			String problem = e.getLocalizedMessage();
			MetadataWithContext3 result = new MetadataWithContext3(new ArrayList<Long>(), null, new ArrayList<String>(), problem, 0);
			results.add(result);
		}

		
		FastVectorHighlighter highlighter = new FastVectorHighlighter(true, true);
		QueryParser qp = new QueryParser("plaintext", new StandardAnalyzer());
		String fieldName = "document_text";
		int fragCharSize = 200;

		Query luceneQuery = null;
			luceneQuery = qp.parse(searchInputs.title);

		for(MetadataWithContext3 un : results) {
			List<String> highlightList = new ArrayList<String>();
			// TODO: Filename
			for(Long id: un.getIds()) {
				String highlight = null;
					highlight = highlighter.getBestFragment(
							highlighter.getFieldQuery(luceneQuery), 
							reader, 
							id.intValue(), 
							fieldName, 
							fragCharSize);
				highlightList.add("... <span class=\"fragment\">" + highlight + "</span> ...");
			}
			un.setHighlight(highlightList);
		}

		if(Globals.TESTING) {
			
			long stopTime = System.currentTimeMillis();
			long elapsedTime = stopTime - startTime;
			System.out.println("Time elapsed: " + elapsedTime);
		}
		
		return results;
	}

	/** Title matches brought to top
	 * @throws ParseException*/
	@Override
	public List<MetadataWithContext> CombinedSearchTitlePriority(SearchInputs searchInputs, SearchType searchType) {
		try {
			long startTime = System.currentTimeMillis();
			List<EISDoc> records = getFilteredRecords(searchInputs);
			
			// Run Lucene query on title if we have one, join with JDBC results, return final results
			if(!searchInputs.title.isBlank()) {
				String formattedTitle = mutateTermModifiers(searchInputs.title);

				HashSet<Long> justRecordIds = new HashSet<Long>();
				for(EISDoc record: records) {
					justRecordIds.add(record.getId());
				}
				
				List<MetadataWithContext> results = titlePrioritySearch(formattedTitle, searchInputs.limit, searchInputs.offset, justRecordIds);

				// Build new result list in the same order but excluding records that don't appear in the first result set (records).
				List<MetadataWithContext> finalResults = new ArrayList<MetadataWithContext>();
				for(int i = 0; i < results.size(); i++) {
					if(justRecordIds.contains(results.get(i).getDoc().getId())) {
						finalResults.add(results.get(i));
					}
				}
				
				if(Globals.TESTING) {
					System.out.println("Records 1 " + records.size());
					System.out.println("Records 2 " + results.size());
				}

				if(Globals.TESTING) {
					long stopTime = System.currentTimeMillis();
					long elapsedTime = stopTime - startTime;
					System.out.println("Manual search time: " + elapsedTime);
				}
				return finalResults;
			} else { // no title: simply return JDBC results...  however they have to be translated
				// TODO: If we care to avoid this, frontend has to know if it's sending a title or not, and ask for the appropriate
				// return type (either EISDoc or MetadataWithContext), and then we need two versions of the search on the backend
				List<MetadataWithContext> finalResults = new ArrayList<MetadataWithContext>();
				for(EISDoc record : records) {
					finalResults.add(new MetadataWithContext(record, "", ""));
				}
				return finalResults;
			}
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	
	}
	
	private List<EISDoc> getFulltextMetaResults(String field, int limit, int offset) throws ParseException{

		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);
		
		QueryParser qp = new QueryParser("title", new StandardAnalyzer());
		qp.setDefaultOperator(Operator.AND);

		// this may throw a ParseException which the caller has to deal with
		Query luceneQuery = qp.parse(field);

//		QueryBuilder queryBuilder = fullTextEntityManager.getSearchFactory()
//				.buildQueryBuilder().forEntity(EISDoc.class).get();
//
//		Query luceneQuery = queryBuilder
//				.simpleQueryString()
//				.onField("title")
//				.withAndAsDefaultOperator()
//				.matching(field)
//				.createQuery();
//		
		org.hibernate.search.jpa.FullTextQuery jpaQuery =
				fullTextEntityManager.createFullTextQuery(luceneQuery, EISDoc.class);
		
		jpaQuery.setMaxResults(limit);
		jpaQuery.setFirstResult(offset);
		
		List<EISDoc> results = jpaQuery.getResultList();
		
		return results;
		
	}

	
	private List<DocumentText> getFulltextResults(String field, int limit, int offset) throws ParseException{
		
		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);

		QueryParser qp = new QueryParser("plaintext", new StandardAnalyzer());
		qp.setDefaultOperator(Operator.AND);

		// this may throw a ParseException which the caller has to deal with
		Query luceneQuery = qp.parse(field);
		
//		QueryBuilder queryBuilder = fullTextEntityManager.getSearchFactory()
//				.buildQueryBuilder().forEntity(DocumentText.class).get();
//
//		Query luceneQuery = queryBuilder
//				.simpleQueryString()
//				.onField("plaintext")
//				.withAndAsDefaultOperator()
//				.matching(field)
//				.createQuery();
		
		org.hibernate.search.jpa.FullTextQuery jpaQuery =
				fullTextEntityManager.createFullTextQuery(luceneQuery, DocumentText.class);
		
		jpaQuery.setMaxResults(limit);
		jpaQuery.setFirstResult(offset);
		
		List<DocumentText> results = jpaQuery.getResultList();
		
		return results;
		
	}
	
	// (probably O(n)) list merge
	private List<MetadataWithContext> mergeResultsWithHighlights(String field, final List<EISDoc> metadataList, final List<DocumentText> textList, final HashSet<Long> justRecordIds) throws IOException, ParseException {
    	// metadatawithcontext results so we can have a text field with all combined text results
		// LinkedHashMap should retain the order of the Lucene-scored results while also using advantages of a hashmap
//	    Map<Long, MetadataWithContext> combinedMap = new LinkedHashMap<Long, MetadataWithContext>();

//	    for (final EISDoc metaDoc : metadataList) {
//	    	MetadataWithContext translatedDoc = new MetadataWithContext(metaDoc, "", "");
//	        combinedMap.put(metaDoc.getId(), translatedDoc);
//	    }
		
		List<MetadataWithContext> combinedResults = new ArrayList<MetadataWithContext>();
		
		for(EISDoc item: metadataList) {
			combinedResults.add(new MetadataWithContext(item, "", ""));
		}

		// build highlighter
		QueryParser qp = new QueryParser("plaintext", new StandardAnalyzer());
		qp.setDefaultOperator(Operator.AND);
		
		// this may throw a ParseException which the caller has to deal with
		Query luceneQuery = qp.parse(field);
		QueryScorer scorer = new QueryScorer(luceneQuery);
		Highlighter highlighter = new Highlighter(globalFormatter, scorer);
		Fragmenter fragmenter = new SimpleFragmenter(fragmentSize);
		highlighter.setTextFragmenter(fragmenter);
		highlighter.setMaxDocCharsToAnalyze(Integer.MAX_VALUE);

		// TODO: This is probably not what we want.  What we may want is to add filename, highlights to EISDoc if it has none already.
		// Else append to list.  Figure out how to either "boost" title results or "sort" or "order" by title.
		// Preferably we don't have to go back to the QueryBuilder to do this because then we have to figure out how to support "?" term modifier
	    for (final DocumentText docText : textList) {

	    	// justRecordIds is our filter, if this doesn't join then don't add it
	    	if(justRecordIds.contains(docText.getEisdoc().getId())) {
	    		final String highlights = getHighlightString(docText.getPlaintext(), highlighter);
		    	if(!highlights.isBlank()) {
		    		combinedResults.add(new MetadataWithContext(docText.getEisdoc(), highlights, docText.getFilename()));
		    	} else {
		    		// shouldn't be possible since we matched
		    		System.out.println("Blank highlight for " + docText.getFilename() + " for term " + field + " text length " + docText.getPlaintext().length());
		    	}
	    	} 
	    }

	    return new ArrayList<MetadataWithContext>(combinedResults);
	}
	
	public List<MetadataWithContext> titlePrioritySearch(String terms, int limit, int offset, HashSet<Long> justRecordIds) throws ParseException {
		if(terms.isBlank()) {
			return new ArrayList<MetadataWithContext>();
		}
		
		// 0: Normalize whitespace and support all term modifiers
	    String formattedTerms = org.apache.commons.lang3.StringUtils.normalizeSpace(mutateTermModifiers(terms).strip());
	    
		// 1: Search title; now have result list in scored order
		List<EISDoc> titleResults = getFulltextMetaResults(formattedTerms, limit, offset);
		// 2: Search file texts
		List<DocumentText> fileTextResults = getFulltextResults(formattedTerms, limit, offset);

		// 3: Add texts to existing objects in list if matching, otherwise append (like a right outer join with left results ordered first)
		try {
			List<MetadataWithContext> combinedResults = mergeResultsWithHighlights(formattedTerms, titleResults, fileTextResults, justRecordIds);

			if(Globals.TESTING) {
				System.out.println("Title results " + titleResults.size());
				System.out.println("Text results " + fileTextResults.size());
				System.out.println("Combined results " + combinedResults.size());
			}

			// 4: Return list
			return combinedResults;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		
	}
	

	// objective: Search both fields at once, connect fragments and return
	public List<MetadataWithContext> lucenePrioritySearch(String terms, int limit, int offset, HashSet<Long> justRecordIds) throws ParseException {
		long startTime = System.currentTimeMillis();
		// Normalize whitespace and support added term modifiers
	    String formattedTerms = org.apache.commons.lang3.StringUtils.normalizeSpace(mutateTermModifiers(terms).strip());

		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);

		// Lucene flattens (denormalizes) and so searching both tables at once is simple enough, 
		// but the results will contain both types mixed together
		MultiFieldQueryParser mfqp = new MultiFieldQueryParser(
					new String[] {"title", "plaintext"},
					new StandardAnalyzer());
		mfqp.setDefaultOperator(Operator.AND);

		Query luceneQuery = mfqp.parse(formattedTerms);
		
		org.hibernate.search.jpa.FullTextQuery jpaQuery =
				fullTextEntityManager.createFullTextQuery(luceneQuery);
		
		jpaQuery.setMaxResults(limit);
		jpaQuery.setFirstResult(offset);

		if(Globals.TESTING) {System.out.println("Query using limit " + limit);}
		
		// Returns a list containing both EISDoc and DocumentText objects.
		List<Object> results = jpaQuery.getResultList();
		
		// init final result list
		List<MetadataWithContext> combinedResultsWithHighlights = new ArrayList<MetadataWithContext>();
		
		// build highlighter
		QueryParser qp = new QueryParser("plaintext", new StandardAnalyzer());
		qp.setDefaultOperator(Operator.AND);
		Query luceneTextOnlyQuery = qp.parse(formattedTerms);
		QueryScorer scorer = new QueryScorer(luceneTextOnlyQuery);
		Highlighter highlighter = new Highlighter(globalFormatter, scorer);
		Fragmenter fragmenter = new SimpleFragmenter(fragmentSize);
		highlighter.setTextFragmenter(fragmenter);
		highlighter.setMaxDocCharsToAnalyze(Integer.MAX_VALUE);
		
		// Condense results:
		// If we have companion results (same EISDoc.ID), combine

		// Quickly build a HashMap of EISDoc (AKA metadata) IDs; these are unique
		// (we'll use these to condense the results on pass 2)
		HashMap<Long, Integer> metaIds = new HashMap<Long, Integer>(results.size());
		int position = 0;
		for (Object result : results) {
			if(result.getClass().equals(EISDoc.class)) {
				metaIds.put(((EISDoc) result).getId(), position);
			}
			position++;
		}
		
		HashMap<Long, Boolean> skipThese = new HashMap<Long, Boolean>();
		
		position = 0;
		for (Object result : results) {

			if(result.getClass().equals(DocumentText.class) && justRecordIds.contains(((DocumentText) result).getEisdoc().getId())) {
				
				try {
					long key = ((DocumentText) result).getEisdoc().getId();

					// Get highlights
					MetadataWithContext combinedResult = new MetadataWithContext(
							((DocumentText) result).getEisdoc(),
							getHighlightString(((DocumentText) result).getPlaintext(), highlighter),
							((DocumentText) result).getFilename());

					// If we have a companion result:
					if(metaIds.containsKey(key)) {
						// If this Text result comes before the Meta result:
						if(metaIds.get(key) > position) {
							// Flag to skip over the Meta result later
							skipThese.put(key, true);
							// Add this combinedResult to List
							combinedResultsWithHighlights.add( combinedResult );
						} else {
							// We already have a companion meta result in the table
							// If existing result has no highlight:
							if(combinedResultsWithHighlights.get(metaIds.get(key)).getHighlight().isBlank()) {
								// "update" that instead of adding this result
								combinedResultsWithHighlights.set(metaIds.get(key), combinedResult);
							} else {
								// Add this combinedResult to List
								combinedResultsWithHighlights.add( combinedResult );
							}
						}
					} else {
						// Add this companionless combinedResult to List
						combinedResultsWithHighlights.add( combinedResult );
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else if(result.getClass().equals(EISDoc.class)) {
				// Add metadata result unless it's flagged for skipping
				if(!skipThese.containsKey(((EISDoc) result).getId())) {
					combinedResultsWithHighlights.add(new MetadataWithContext(((EISDoc) result),"",""));
				}
			}
			position++;
		}
		
		if(Globals.TESTING) {
			System.out.println("Results #: " + results.size());
			
			long stopTime = System.currentTimeMillis();
			long elapsedTime = stopTime - startTime;
			System.out.println("Time elapsed: " + elapsedTime);
		}

		return combinedResultsWithHighlights;
	}
	
	@Deprecated
	@SuppressWarnings("unchecked")
	public List<MetadataWithContext2> searchNoContext(String terms, int limit, int offset, HashSet<Long> justRecordIds) throws ParseException {
		long startTime = System.currentTimeMillis();

		// Normalize whitespace and support added term modifiers
	    String formattedTerms = org.apache.commons.lang3.StringUtils.normalizeSpace(mutateTermModifiers(terms).strip());

		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);

		// Lucene flattens (denormalizes) and so searching both tables at once is simple enough, 
		// but the results will contain both types mixed together
		MultiFieldQueryParser mfqp = new MultiFieldQueryParser(
					new String[] {"title", "plaintext"},
					new StandardAnalyzer());
		mfqp.setDefaultOperator(Operator.AND);

		Query luceneQuery = mfqp.parse(formattedTerms);
		
//			org.hibernate.search.jpa.FullTextQuery jpaQuery =
//					fullTextEntityManager.createFullTextQuery(luceneQuery, DocumentText.class); // filters only DocumentText results
		org.hibernate.search.jpa.FullTextQuery jpaQuery =
				fullTextEntityManager.createFullTextQuery(luceneQuery);

//		jpaQuery.setProjection(ProjectionConstants.ID);
//		jpaQuery.setProjection(ProjectionConstants.ID, ProjectionConstants.OBJECT_CLASS);
//		jpaQuery.setProjection(ProjectionConstants.ID, ProjectionConstants.SCORE, "filename");
		jpaQuery.setMaxResults(1000000);
		jpaQuery.setFirstResult(0);
		
		// Lazy fetching isn't so easy here with combined results, so the goal is to get the order
		// first and then get all of the results maintaining that order but without getting full
		// texts which is slow and also overflows the heap
		
		// Could potentially try to get ProjectionConstants.ID and ProjectionConstants.SCORE
		// for two separate searches, join and sort by score,
		// then get the metadata and filenames.  This would maintain the order.
		

		if(Globals.TESTING) {System.out.println("Query using limit " + limit);}
		
		// Returns a list containing both EISDoc and DocumentText objects.
		List<Object> results = jpaQuery.getResultList();
		
//		Class<?> clazz = results.get(0).getClass();
//		System.out.println(clazz);
//		System.out.println(clazz.getClass());
//		for(Field field : clazz.getDeclaredFields()) {
//			System.out.println(field.getName());
//		}
//		if(Globals.TESTING) {
//			System.out.println(results.get(0).getId().toString());
//			System.out.println(results.get(0).getFilename());
//		}
		
		// init final result list
		List<MetadataWithContext2> combinedResults = new ArrayList<MetadataWithContext2>();
		
		// Condense results:
		// If we have companion results (same EISDoc.ID), combine

		// Quickly build a HashMap of EISDoc (AKA metadata) IDs; these are unique
		// (we'll use these to condense the results on pass 2)
		HashMap<Long, Integer> metaIds = new HashMap<Long, Integer>(results.size());
		int position = 0;
		for (Object result : results) {
			if(result.getClass().equals(EISDoc.class)) {
				metaIds.put(((EISDoc) result).getId(), position);
			}
			position++;
		}
		
		HashMap<Long, Boolean> skipThese = new HashMap<Long, Boolean>();
		HashMap<Long, Integer> added = new HashMap<Long, Integer>();
		
		// Handle DocumentText results
		position = 0;
		for (Object result : results) {
			if(result.getClass().equals(DocumentText.class) && justRecordIds.contains(((DocumentText) result).getEisdoc().getId())) {
				
				try {
					long key = ((DocumentText) result).getEisdoc().getId();

					// Get filename
					MetadataWithContext2 combinedResult = new MetadataWithContext2(
							((DocumentText) result).getEisdoc(),
							new ArrayList<String>(),
							((DocumentText) result).getFilename(),0);

					// 1. If we have already have a title result set skip flag
					if(metaIds.containsKey(key) && (metaIds.get(key) > position)) { // If this Text result comes before the Meta result
							// Flag to skip over the Meta result later
							skipThese.put(key, true);
					} 
					// 2. If this is the first non-title (text content) result, add new.
					if(!added.containsKey(key)) {
						combinedResults.add( combinedResult );
						added.put( key, position );
					} else {
						// 3. If we already have this result with no filename, add new filename.
						if(combinedResults.get(added.get(key)).getFilenames().isBlank()) {
							// "update" that instead of adding this result
							combinedResults.set(added.get(key), combinedResult);
						} else {
							// 4. If we have this WITH filename, concat.
							if(Globals.TESTING) {
								System.out.println("Adding filename to existing record: " + combinedResult.getFilenames());
							}
							// Add this combinedResult's filename to filename list
							String currentFilename = combinedResults.get(added.get(key)).getFilenames();
							// > is not a valid directory/filename char, so should work as delimiter
							combinedResults.get(added.get(key))
								.setFilenames(
									currentFilename.concat(">" + combinedResult.getFilenames())
								);
						}
					}
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else if(result.getClass().equals(EISDoc.class)) {
				// Add metadata result unless it's flagged for skipping
				if(!skipThese.containsKey(((EISDoc) result).getId())) {
					combinedResults.add(new MetadataWithContext2(((EISDoc) result),new ArrayList<String>(),"",0));
				}
			}
			position++;
		}
		
		if(Globals.TESTING) {
			System.out.println("Results #: " + results.size());
			
			long stopTime = System.currentTimeMillis();
			long elapsedTime = stopTime - startTime;
			System.out.println("Time elapsed: " + elapsedTime);
		}

		return combinedResults;
	}
	
//	public List<String> getHighlightsFVH(UnhighlightedDTO unhighlighted) throws IOException {
//
//	}
	
	public ArrayList<ArrayList<String>> getHighlights(UnhighlightedDTO unhighlighted) throws ParseException {
		long startTime = System.currentTimeMillis();
		// Normalize whitespace and support added term modifiers
	    String formattedTerms = org.apache.commons.lang3.StringUtils.normalizeSpace(mutateTermModifiers(unhighlighted.getTerms()).strip());
		
		// build highlighter with StandardAnalyzer
		QueryParser qp = new QueryParser("plaintext", new StandardAnalyzer());
		qp.setDefaultOperator(Operator.AND);
		Query luceneTextOnlyQuery = qp.parse(formattedTerms);
		QueryScorer scorer = new QueryScorer(luceneTextOnlyQuery);
		
		Highlighter highlighter = new Highlighter(globalFormatter, scorer);
		
		Fragmenter fragmenter = new SimpleFragmenter(bigFragmentSize);
		highlighter.setTextFragmenter(fragmenter);
		highlighter.setMaxDocCharsToAnalyze(Integer.MAX_VALUE);
		
		
		ArrayList<ArrayList<String>> results = new ArrayList<ArrayList<String>>();
		
		for(Unhighlighted input : unhighlighted.getUnhighlighted()) {
			ArrayList<String> result = new ArrayList<String>();

			// Run query to get each text via eisdoc ID and filename?
			// Need to split filenames by >
			String[] filenames = input.getFilename().split(">");
			List<String> texts = new ArrayList<String>();
			for(String filename : filenames) {
				ArrayList<String> inputList = new ArrayList<String>();
				inputList.add(input.getId().toString());
				inputList.add(filename);
				List<String> records = jdbcTemplate.query
				(
					"SELECT plaintext FROM test.document_text WHERE document_id = (?) AND filename=(?)", 
					inputList.toArray(new Object[] {}),
					(rs, rowNum) -> new String(
						rs.getString("plaintext")
					)
				);
				if(records.size()>0) {
					String text = records.get(0);
					texts.add(text);

					if(Globals.TESTING){
						System.out.println("ID: " + input.getId().toString() + "; Filename: " + filename);
					}
				}
			}
			
			
//				Optional<EISDoc> doc = DocRepository.findById(input.getId());
//				String text = TextRepository.findByEisdocAndFilenameIn(doc.get(), filename).getText();
			StandardAnalyzer stndrdAnalyzer = new StandardAnalyzer();
			for(String text : texts) {
				TokenStream tokenStream = stndrdAnalyzer.tokenStream("plaintext", new StringReader(text));

				try {
					// Add ellipses to denote that these are text fragments within the string
					String highlight = highlighter.getBestFragments(tokenStream, text, 1, " ...</span><span class=\"fragment\">... ");
					
					if(highlight.length() > 0) {
						result.add("<span class=\"fragment\">... " + org.apache.commons.lang3.StringUtils.normalizeSpace(highlight).strip().concat(" ...</span>"));
					}
				} catch (InvalidTokenOffsetsException | IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} finally {
					try {
						tokenStream.close();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
			stndrdAnalyzer.close();
			results.add(result);
		}
		

		if(Globals.TESTING) {
			System.out.println("Results #: " + results.size());
			
			long stopTime = System.currentTimeMillis();
			long elapsedTime = stopTime - startTime;
			System.out.println("Time elapsed: " + elapsedTime);
		}
		
		return results;
	}
}
