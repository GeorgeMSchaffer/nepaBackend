package nepaBackend;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.hibernate.search.query.dsl.QueryBuilder;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.index.Term;
import org.apache.lucene.queries.TermsQuery;
import org.apache.lucene.queryparser.surround.parser.QueryParser;
import org.apache.lucene.queryparser.surround.query.BasicQueryFactory;
import org.apache.lucene.queryparser.surround.query.SrndQuery;
import org.apache.lucene.sandbox.queries.FuzzyLikeThisQuery;
import org.apache.lucene.search.FuzzyQuery;
import org.apache.lucene.search.MultiPhraseQuery;
import org.apache.lucene.search.PhraseQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.highlight.Fragmenter;
import org.apache.lucene.search.highlight.Highlighter;
import org.apache.lucene.search.highlight.InvalidTokenOffsetsException;
import org.apache.lucene.search.highlight.QueryScorer;
import org.apache.lucene.search.highlight.SimpleFragmenter;
import org.apache.lucene.search.highlight.SimpleHTMLFormatter;
import org.apache.lucene.search.spans.SpanMultiTermQueryWrapper;
import org.apache.lucene.search.spans.SpanNearQuery;
import org.apache.lucene.search.spans.SpanQuery;
import org.hibernate.search.engine.ProjectionConstants;
import org.hibernate.search.jpa.FullTextEntityManager;
import org.hibernate.search.jpa.Search;

import nepaBackend.controller.MetadataWithContext;
import nepaBackend.enums.SearchType;
import nepaBackend.model.DocumentText;
import nepaBackend.model.EISDoc;

// TODO: Probably want a way to search for many/expanded highlights/context from one archive only
public class CustomizedTextRepositoryImpl implements CustomizedTextRepository {
	@PersistenceContext
	private EntityManager em;

	private static int numberOfFragmentsMax = 5;
	private static int fragmentSize = 250;
	
	private static int fuzzyLevel = 0;

	/** Return all records matching terms (no highlights/context) */
	@SuppressWarnings("unchecked")
	@Override
	public List<EISDoc> search(String terms, int limit, int offset) {
		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em); // Create fulltext entity manager
			
		QueryBuilder queryBuilder = fullTextEntityManager.getSearchFactory()
				.buildQueryBuilder().forEntity(DocumentText.class).get();

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
		Query luceneQuery = queryBuilder
				.keyword()
				.fuzzy()
				.withEditDistanceUpTo(fuzzyLevel) // max: 2; default: 2; aka maximum fuzziness
				.onField("plaintext")
				.matching(terms)
				.createQuery();

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
		// TODO: Can get filenames also, display those on frontend and no longer need DISTINCT (would require a new POJO, different structure than List<EISDoc>)
		javax.persistence.Query query = em.createQuery("SELECT DISTINCT doc.eisdoc FROM DocumentText doc WHERE doc.id IN :ids");
		query.setParameter("ids", new_ids);

		List<EISDoc> docs = query.getResultList();

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
	
	/** Return all highlights with context and document ID for matching terms (term phrase?) */
	@SuppressWarnings("unchecked")
	@Override
	public List<MetadataWithContext> metaContext(String terms, int limit, int offset, SearchType searchType) {
		
		terms = escapeSpecialCharacters(terms);
		FullTextEntityManager fullTextEntityManager = Search.getFullTextEntityManager(em);

		QueryBuilder queryBuilder = fullTextEntityManager.getSearchFactory()
				.buildQueryBuilder().forEntity(DocumentText.class).get();
		Query luceneQuery = null;
		
		boolean fuzzy = true;
		if(fuzzy) {
			luceneQuery = queryBuilder
					.keyword()
					.fuzzy()
					.withEditDistanceUpTo(fuzzyLevel) // max: 2; default: 2; aka maximum fuzziness
					.onField("plaintext")
					.matching(terms)
					.createQuery();
			
		} else {
			luceneQuery = queryBuilder
					.phrase()
						.withSlop(0) // default: 0 (note: doesn't work as expected)
					.onField("plaintext")
					.sentence(terms)
					.createQuery();
		}
			
		// wrap Lucene query in a javax.persistence.Query
		javax.persistence.Query jpaQuery =
		fullTextEntityManager.createFullTextQuery(luceneQuery, DocumentText.class);
		
		jpaQuery.setMaxResults(limit);
		jpaQuery.setFirstResult(offset);
		
		// execute search
		List<DocumentText> docList = jpaQuery.getResultList();
		List<MetadataWithContext> highlightList = new ArrayList<MetadataWithContext>();
		

		
		
		SimpleHTMLFormatter formatter = new SimpleHTMLFormatter("<span class=\"highlight\">","</span>");

		// Logic for exact phrase vs. all-word query
		QueryScorer scorer = null;
		String[] words = terms.split(" ");
		if(searchType == SearchType.ALL) { // .equals uses == internally
			if(fuzzy) {
				// New search code
				FuzzyLikeThisQuery fuzzyQuery = new FuzzyLikeThisQuery(32, new StandardAnalyzer());
				fuzzyQuery.addTerms(terms, "f", fuzzyLevel, 0);
				scorer = new QueryScorer(fuzzyQuery);
			} else {
				// Old search code
				List<Term> termWords = new ArrayList<Term>();
				for (String word: words) {
					termWords.add(new Term("f", word));
				}
				
				TermsQuery query = new TermsQuery(termWords);
				scorer = new QueryScorer(query);
			}
		} else {
			// Oldest code (most precision required)
			PhraseQuery query = new PhraseQuery("f", words);
			scorer = new QueryScorer(query);
		}

		Highlighter highlighter = new Highlighter(formatter, scorer);
		Fragmenter fragmenter = new SimpleFragmenter(fragmentSize);
		highlighter.setTextFragmenter(fragmenter);
		highlighter.setMaxDocCharsToAnalyze(Integer.MAX_VALUE);
		
		
		
		// Use PhraseQuery or TermQuery to get results for matching records
		for (DocumentText doc: docList) {
			try {
				String highlight = getHighlightString(doc.getPlaintext(), highlighter);
				if(highlight.length() > 0) { // Length 0 shouldn't be possible since we are working on matching results already
					highlightList.add(new MetadataWithContext(doc.getEisdoc(), highlight, doc.getFilename()));
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} finally {
				fullTextEntityManager.close();
			}
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
	
	// Given text and highlighter, return highlights (fragments) for text
	private static String getHighlightString (String text, Highlighter highlighter) throws IOException {
		
		
		StandardAnalyzer stndrdAnalyzer = new StandardAnalyzer();
		TokenStream tokenStream = stndrdAnalyzer.tokenStream("f", new StringReader(text));
		String result = "";
		
		try {
			// Add ellipses to denote that these are text fragments within the string
			result = highlighter.getBestFragments(tokenStream, text, numberOfFragmentsMax, " ...</span><br /><span class=\"fragment\">... ");
//			System.out.println(result);
			if(result.length()>0) {
				result = "<span class=\"fragment\">... " + (result.replaceAll("\\n+", " ")).trim().concat(" ...</span>");
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
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
	}
	
// As long as we use the ORM to delete DocumentText records, Lucene will know about it and delete them from its index
//	public boolean delete(Long id) {
//		return true;
//	}
	
	/** Escape what Lucene defines as special characters to prevent things like unintentionally excluding the word "green" 
	 * 	when searching for "Duwamish-Green".  At the same time, Lucene does not index characters like "-", so prevent
	 *  searching for "Duwamish-Green" at all and instead search for "duwamish green".  This could change if a different 
	 *  analyzer is used.  */
	private String escapeSpecialCharacters(String inputString) {
		// Lucene supports case-sensitiev inpput, but I'm indexing only lowercase words and no punctuation
		inputString = inputString.toLowerCase();
		//+ - && || ! ( ) { } [ ] ^ \" ~ * ? : \\ /
		final String[] metaCharacters = {"+","-","&&","||","!","(",")","{","}","[","]","^","\"","~","*","?",":","/","  "};
		
		for (int i = 0 ; i < metaCharacters.length ; i++){
			if(inputString.contains(metaCharacters[i])){
				// Lucene can use special characters, but until we decide how to handle that power just remove them all
//				inputString = inputString.replace(metaCharacters[i],"\\"+metaCharacters[i]);
				inputString = inputString.replace(metaCharacters[i]," ") // replace special characters with spaces
						.trim(); // extra spaces may mean no results when looking for an exact phrase
			}
		}
		return inputString;
	}
}
