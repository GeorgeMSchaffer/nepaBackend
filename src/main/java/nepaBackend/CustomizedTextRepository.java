package nepaBackend;

import java.util.List;

import org.apache.lucene.queryparser.classic.ParseException;

import nepaBackend.controller.MetadataWithContext;
import nepaBackend.enums.SearchType;
import nepaBackend.model.EISDoc;
import nepaBackend.pojo.SearchInputs;

public interface CustomizedTextRepository {
	List<EISDoc> search(String term, int limit, int offset) throws ParseException;
//	List<String> searchContext(String term, int limit, int offset);
	List<MetadataWithContext> metaContext(String term, int limit, int offset, SearchType searchType) throws ParseException;

	List<EISDoc> metadataSearch(SearchInputs searchInputs, int limit, int offset, SearchType searchType);

	boolean sync();
	
	List<MetadataWithContext> CombinedSearchTitlePriority(SearchInputs searchInputs, SearchType searchType);
	List<MetadataWithContext> CombinedSearchLucenePriority(SearchInputs searchInputs, SearchType searchType);
	List<MetadataWithContext> CombinedSearchNoContext(SearchInputs searchInputs, SearchType searchType);
}
