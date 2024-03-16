package ch.bfh.vcbbs.types;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Java VC Representation
 */
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class VC{

    @JsonProperty("@context")
    private final String[] context;
    private final String[] type;
    private final String issuer;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Date validFrom;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String id;
    private final Map<String, Object> credentialSubject = new HashMap<>();
    @JsonIgnore
    private static final ObjectMapper mapper = new ObjectMapper();

    @JsonCreator
    public VC(@JsonProperty("@context")String[] context, @JsonProperty("type")String[] type, @JsonProperty("issuer")String issuer){
        this.context = context;
        this.type = type;
        this.issuer = issuer;
    }

    @JsonSetter
    public void setId(String id){
        this.id = id;
    }

    @JsonSetter
    public void setValidFrom(Date validFrom){
        // Todo: Set correct type
        this.validFrom = validFrom;
    }

    public void addAttribute(String key, Object value){
        credentialSubject.put(key, value);
    }

    public static String serialize(VC vc) throws JsonProcessingException {
        return mapper.writeValueAsString(vc);
    }

    public static VC deserialize(String vc) throws JsonProcessingException {
        return mapper.readValue(vc, VC.class);
    }
}
