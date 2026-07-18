#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <sstream>

// A heuristic BPE token estimator
int estimateTokens(const std::string& text) {
    int count = 0;
    bool in_word = false;
    int word_len = 0;
    for (char c : text) {
        if (std::isalnum(c) || c == '_') {
            if (!in_word) {
                count++;
                in_word = true;
                word_len = 0;
            }
            word_len++;
            // BPE subword splitting: long tokens split into multiple subwords
            if (word_len > 0 && word_len % 5 == 0) { count++; }
        } else if (std::isspace(c)) {
            in_word = false;
            word_len = 0;
        } else {
            // Punctuation is usually its own token
            count++;
            in_word = false;
            word_len = 0;
        }
    }
    return count;
}

struct PayloadSet {
    std::string name;
    std::string top;
    std::string verbose_json;
    std::string minimal_json;
    std::string compact_json;
    std::string yaml;
};

int main() {
    std::vector<PayloadSet> scenarios = {
        // Scenario 1: Refactor request
        {
            "Refactor Request",
            // LLM-TOP
            "VER:LLM-TOPv1 CHK:sha256:1234 AGT:coder UID:anon TIM:2026-07-18 REQID:req_refactor FALLBACK:json\n"
            "[CODER] tgt:src/auth.ts:cap=secret;ttl=3600 act:refactor GL:improve_validation\n"
            "!read[path=src/auth.ts]\n"
            "!write[path=src/auth.ts;content=\"new validation code\"]>commit\n",
            // Verbose JSON
            "{\n"
            "  \"version\": \"LLM-TOPv1\",\n"
            "  \"checksum\": \"sha256:1234\",\n"
            "  \"agent\": \"coder\",\n"
            "  \"uid\": \"anon\",\n"
            "  \"time\": \"2026-07-18\",\n"
            "  \"reqid\": \"req_refactor\",\n"
            "  \"fallback\": \"json\",\n"
            "  \"statements\": [\n"
            "    {\n"
            "      \"role\": \"CODER\",\n"
            "      \"kvpairs\": {\n"
            "        \"tgt\": \"src/auth.ts:cap=secret;ttl=3600\",\n"
            "        \"act\": \"refactor\",\n"
            "        \"GL\": \"improve_validation\"\n"
            "      },\n"
            "      \"commands\": [\n"
            "        {\n"
            "          \"tool\": \"read\",\n"
            "          \"args\": { \"path\": \"src/auth.ts\" }\n"
            "        },\n"
            "        {\n"
            "          \"tool\": \"write\",\n"
            "          \"method\": \"commit\",\n"
            "          \"args\": {\n"
            "            \"path\": \"src/auth.ts\",\n"
            "            \"content\": \"new validation code\"\n"
            "          }\n"
            "        }\n"
            "      ]\n"
            "    }\n"
            "  ]\n"
            "}",
            // Minimal JSON
            "{\"v\":\"LLM-TOPv1\",\"c\":\"sha256:1234\",\"a\":\"coder\",\"u\":\"anon\",\"t\":\"2026-07-18\",\"r\":\"req_refactor\",\"f\":\"json\",\"s\":[{\"o\":\"CODER\",\"k\":{\"t\":\"src/auth.ts:cap=secret;ttl=3600\",\"a\":\"refactor\",\"G\":\"improve_validation\"},\"c\":[{\"t\":\"read\",\"a\":{\"p\":\"src/auth.ts\"}},{\"t\":\"write\",\"m\":\"commit\",\"a\":{\"p\":\"src/auth.ts\",\"c\":\"new validation code\"}}]}]}",
            // Compact JSON
            "{\"version\":\"LLM-TOPv1\",\"checksum\":\"sha256:1234\",\"agent\":\"coder\",\"uid\":\"anon\",\"time\":\"2026-07-18\",\"reqid\":\"req_refactor\",\"fallback\":\"json\",\"statements\":[{\"role\":\"CODER\",\"kvpairs\":{\"tgt\":\"src/auth.ts:cap=secret;ttl=3600\",\"act\":\"refactor\",\"GL\":\"improve_validation\"},\"commands\":[{\"tool\":\"read\",\"args\":{\"path\":\"src/auth.ts\"}},{\"tool\":\"write\",\"method\":\"commit\",\"args\":{\"path\":\"src/auth.ts\",\"content\":\"new validation code\"}}]}]}",
            // YAML
            "version: LLM-TOPv1\n"
            "checksum: sha256:1234\n"
            "agent: coder\n"
            "uid: anon\n"
            "time: 2026-07-18\n"
            "reqid: req_refactor\n"
            "fallback: json\n"
            "statements:\n"
            "  - role: CODER\n"
            "    kvpairs:\n"
            "      tgt: src/auth.ts:cap=secret;ttl=3600\n"
            "      act: refactor\n"
            "      GL: improve_validation\n"
            "    commands:\n"
            "      - tool: read\n"
            "        args:\n"
            "          path: src/auth.ts\n"
            "      - tool: write\n"
            "        method: commit\n"
            "        args:\n"
            "          path: src/auth.ts\n"
            "          content: new validation code\n"
        },
        // Scenario 2: Multi-file plan
        {
            "Multi-file Plan",
            // LLM-TOP
            "VER:LLM-TOPv1 CHK:sha256:5678 AGT:planner UID:anon TIM:2026-07-18 REQID:req_multi FALLBACK:json\n"
            "[PLAN] tgt:workspace act:multi-edit GL:refactor_db TD:update_schemas\n"
            "!read[path=src/db/users.ts]\n"
            "!read[path=src/db/posts.ts]\n"
            "!write[path=src/db/users.ts;content=\"schema users updates\"]\n"
            "!write[path=src/db/posts.ts;content=\"schema posts updates\"]\n",
            // Verbose JSON
            "{\n"
            "  \"version\": \"LLM-TOPv1\",\n"
            "  \"checksum\": \"sha256:5678\",\n"
            "  \"agent\": \"planner\",\n"
            "  \"uid\": \"anon\",\n"
            "  \"time\": \"2026-07-18\",\n"
            "  \"reqid\": \"req_multi\",\n"
            "  \"fallback\": \"json\",\n"
            "  \"statements\": [\n"
            "    {\n"
            "      \"role\": \"PLAN\",\n"
            "      \"kvpairs\": {\n"
            "        \"tgt\": \"workspace\",\n"
            "        \"act\": \"multi-edit\",\n"
            "        \"GL\": \"refactor_db\",\n"
            "        \"TD\": \"update_schemas\"\n"
            "      },\n"
            "      \"commands\": [\n"
            "        { \"tool\": \"read\", \"args\": { \"path\": \"src/db/users.ts\" } },\n"
            "        { \"tool\": \"read\", \"args\": { \"path\": \"src/db/posts.ts\" } },\n"
            "        { \"tool\": \"write\", \"args\": { \"path\": \"src/db/users.ts\", \"content\": \"schema users updates\" } },\n"
            "        { \"tool\": \"write\", \"args\": { \"path\": \"src/db/posts.ts\", \"content\": \"schema posts updates\" } }\n"
            "      ]\n"
            "    }\n"
            "  ]\n"
            "}",
            // Minimal JSON
            "{\"v\":\"LLM-TOPv1\",\"c\":\"sha256:5678\",\"a\":\"planner\",\"u\":\"anon\",\"t\":\"2026-07-18\",\"r\":\"req_multi\",\"f\":\"json\",\"s\":[{\"o\":\"PLAN\",\"k\":{\"t\":\"workspace\",\"a\":\"multi-edit\",\"G\":\"refactor_db\",\"T\":\"update_schemas\"},\"c\":[{\"t\":\"read\",\"a\":{\"p\":\"src/db/users.ts\"}},{\"t\":\"read\",\"a\":{\"p\":\"src/db/posts.ts\"}},{\"t\":\"write\",\"a\":{\"p\":\"src/db/users.ts\",\"c\":\"schema users updates\"}},{\"t\":\"write\",\"a\":{\"p\":\"src/db/posts.ts\",\"c\":\"schema posts updates\"}}]}]}",
            // Compact JSON
            "{\"version\":\"LLM-TOPv1\",\"checksum\":\"sha256:5678\",\"agent\":\"planner\",\"uid\":\"anon\",\"time\":\"2026-07-18\",\"reqid\":\"req_multi\",\"fallback\":\"json\",\"statements\":[{\"role\":\"PLAN\",\"kvpairs\":{\"tgt\":\"workspace\",\"act\":\"multi-edit\",\"GL\":\"refactor_db\",\"TD\":\"update_schemas\"},\"commands\":[{\"tool\":\"read\",\"args\":{\"path\":\"src/db/users.ts\"}},{\"tool\":\"read\",\"args\":{\"path\":\"src/db/posts.ts\"}},{\"tool\":\"write\",\"args\":{\"path\":\"src/db/users.ts\",\"content\":\"schema users updates\"}},{\"tool\":\"write\",\"args\":{\"path\":\"src/db/posts.ts\",\"content\":\"schema posts updates\"}}]}]}",
            // YAML
            "version: LLM-TOPv1\n"
            "checksum: sha256:5678\n"
            "agent: planner\n"
            "uid: anon\n"
            "time: 2026-07-18\n"
            "reqid: req_multi\n"
            "fallback: json\n"
            "statements:\n"
            "  - role: PLAN\n"
            "    kvpairs:\n"
            "      tgt: workspace\n"
            "      act: multi-edit\n"
            "      GL: refactor_db\n"
            "      TD: update_schemas\n"
            "    commands:\n"
            "      - tool: read\n"
            "        args:\n"
            "          path: src/db/users.ts\n"
            "      - tool: read\n"
            "        args:\n"
            "          path: src/db/posts.ts\n"
            "      - tool: write\n"
            "        args:\n"
            "          path: src/db/users.ts\n"
            "          content: schema users updates\n"
            "      - tool: write\n"
            "        args:\n"
            "          path: src/db/posts.ts\n"
            "          content: schema posts updates\n"
        },
        // Scenario 3: Debugging session
        {
            "Debugging Session",
            // LLM-TOP
            "VER:LLM-TOPv1 CHK:sha256:9abc AGT:debugger UID:anon TIM:2026-07-18 REQID:req_debug FALLBACK:json\n"
            "[DEBUG] tgt:server.log act:diagnose GL:fix_crash TD:check_stacktrace\n"
            "!grep[pattern=\"NullPointerException\";path=server.log]\n"
            "!run[target=server;args=\"--dry-run\"]>diagnose\n",
            // Verbose JSON
            "{\n"
            "  \"version\": \"LLM-TOPv1\",\n"
            "  \"checksum\": \"sha256:9abc\",\n"
            "  \"agent\": \"debugger\",\n"
            "  \"uid\": \"anon\",\n"
            "  \"time\": \"2026-07-18\",\n"
            "  \"reqid\": \"req_debug\",\n"
            "  \"fallback\": \"json\",\n"
            "  \"statements\": [\n"
            "    {\n"
            "      \"role\": \"DEBUG\",\n"
            "      \"kvpairs\": {\n"
            "        \"tgt\": \"server.log\",\n"
            "        \"act\": \"diagnose\",\n"
            "        \"GL\": \"fix_crash\",\n"
            "        \"TD\": \"check_stacktrace\"\n"
            "      },\n"
            "      \"commands\": [\n"
            "        {\n"
            "          \"tool\": \"grep\",\n"
            "          \"args\": { \"pattern\": \"NullPointerException\", \"path\": \"server.log\" }\n"
            "        },\n"
            "        {\n"
            "          \"tool\": \"run\",\n"
            "          \"method\": \"diagnose\",\n"
            "          \"args\": { \"target\": \"server\", \"args\": \"--dry-run\" }\n"
            "        }\n"
            "      ]\n"
            "    }\n"
            "  ]\n"
            "}",
            // Minimal JSON
            "{\"v\":\"LLM-TOPv1\",\"c\":\"sha256:9abc\",\"a\":\"debugger\",\"u\":\"anon\",\"t\":\"2026-07-18\",\"r\":\"req_debug\",\"f\":\"json\",\"s\":[{\"o\":\"DEBUG\",\"k\":{\"t\":\"server.log\",\"a\":\"diagnose\",\"G\":\"fix_crash\",\"T\":\"check_stacktrace\"},\"c\":[{\"t\":\"grep\",\"a\":{\"p\":\"NullPointerException\",\"h\":\"server.log\"}},{\"t\":\"run\",\"m\":\"diagnose\",\"a\":{\"t\":\"server\",\"a\":\"--dry-run\"}}]}]}",
            // Compact JSON
            "{\"version\":\"LLM-TOPv1\",\"checksum\":\"sha256:9abc\",\"agent\":\"debugger\",\"uid\":\"anon\",\"time\":\"2026-07-18\",\"reqid\":\"req_debug\",\"fallback\":\"json\",\"statements\":[{\"role\":\"DEBUG\",\"kvpairs\":{\"tgt\":\"server.log\",\"act\":\"diagnose\",\"GL\":\"fix_crash\",\"TD\":\"check_stacktrace\"},\"commands\":[{\"tool\":\"grep\",\"args\":{\"pattern\":\"NullPointerException\",\"path\":\"server.log\"}},{\"tool\":\"run\",\"method\":\"diagnose\",\"args\":{\"target\":\"server\",\"args\":\"--dry-run\"}}]}]}",
            // YAML
            "version: LLM-TOPv1\n"
            "checksum: sha256:9abc\n"
            "agent: debugger\n"
            "uid: anon\n"
            "time: 2026-07-18\n"
            "reqid: req_debug\n"
            "fallback: json\n"
            "statements:\n"
            "  - role: DEBUG\n"
            "    kvpairs:\n"
            "      tgt: server.log\n"
            "      act: diagnose\n"
            "      GL: fix_crash\n"
            "      TD: check_stacktrace\n"
            "    commands:\n"
            "      - tool: grep\n"
            "        args:\n"
            "          pattern: NullPointerException\n"
            "          path: server.log\n"
            "      - tool: run\n"
            "        method: diagnose\n"
            "        args:\n"
            "          target: server\n"
            "          args: --dry-run\n"
        },
        // Scenario 4: Long-context read
        {
            "Long-context Read",
            // LLM-TOP
            "VER:LLM-TOPv1 CHK:sha256:def0 AGT:reader UID:anon TIM:2026-07-18 REQID:req_read FALLBACK:json\n"
            "[READER] tgt:docs/large_spec.md act:analyze GL:summarize_architecture TD:verify_requirements\n"
            "!read[path=docs/large_spec.md]\n",
            // Verbose JSON
            "{\n"
            "  \"version\": \"LLM-TOPv1\",\n"
            "  \"checksum\": \"sha256:def0\",\n"
            "  \"agent\": \"reader\",\n"
            "  \"uid\": \"anon\",\n"
            "  \"time\": \"2026-07-18\",\n"
            "  \"reqid\": \"req_read\",\n"
            "  \"fallback\": \"json\",\n"
            "  \"statements\": [\n"
            "    {\n"
            "      \"role\": \"READER\",\n"
            "      \"kvpairs\": {\n"
            "        \"tgt\": \"docs/large_spec.md\",\n"
            "        \"act\": \"analyze\",\n"
            "        \"GL\": \"summarize_architecture\",\n"
            "        \"TD\": \"verify_requirements\"\n"
            "      },\n"
            "      \"commands\": [\n"
            "        { \"tool\": \"read\", \"args\": { \"path\": \"docs/large_spec.md\" } }\n"
            "      ]\n"
            "    }\n"
            "  ]\n"
            "}",
            // Minimal JSON
            "{\"v\":\"LLM-TOPv1\",\"c\":\"sha256:def0\",\"a\":\"reader\",\"u\":\"anon\",\"t\":\"2026-07-18\",\"r\":\"req_read\",\"f\":\"json\",\"s\":[{\"o\":\"READER\",\"k\":{\"t\":\"docs/large_spec.md\",\"a\":\"analyze\",\"G\":\"summarize_architecture\",\"T\":\"verify_requirements\"},\"c\":[{\"t\":\"read\",\"a\":{\"p\":\"docs/large_spec.md\"}}]}]}",
            // Compact JSON
            "{\"version\":\"LLM-TOPv1\",\"checksum\":\"sha256:def0\",\"agent\":\"reader\",\"uid\":\"anon\",\"time\":\"2026-07-18\",\"reqid\":\"req_read\",\"fallback\":\"json\",\"statements\":[{\"role\":\"READER\",\"kvpairs\":{\"tgt\":\"docs/large_spec.md\",\"act\":\"analyze\",\"GL\":\"summarize_architecture\",\"TD\":\"verify_requirements\"},\"commands\":[{\"tool\":\"read\",\"args\":{\"path\":\"docs/large_spec.md\"}}]}]}",
            // YAML
            "version: LLM-TOPv1\n"
            "checksum: sha256:def0\n"
            "agent: reader\n"
            "uid: anon\n"
            "time: 2026-07-18\n"
            "reqid: req_read\n"
            "fallback: json\n"
            "statements:\n"
            "  - role: READER\n"
            "    kvpairs:\n"
            "      tgt: docs/large_spec.md\n"
            "      act: analyze\n"
            "      GL: summarize_architecture\n"
            "      TD: verify_requirements\n"
            "    commands:\n"
            "      - tool: read\n"
            "        args:\n"
            "          path: docs/large_spec.md\n"
        },
        // Scenario 5: Synthetic large message
        {
            "Synthetic Large Message",
            // LLM-TOP
            "VER:LLM-TOPv1 CHK:sha256:789a AGT:synth UID:anon TIM:2026-07-18 REQID:req_synth FALLBACK:json\n"
            "[SYNTH] tgt:pipeline act:test GL:load_test TD:generate_data\n"
            "!call[api=auth;payload=\"{\\\"user\\\":\\\"test_user\\\",\\\"token\\\":\\\"temp_token_123\\\"}\"]\n"
            "!call[api=users;payload=\"{\\\"action\\\":\\\"create\\\",\\\"name\\\":\\\"Alice\\\"}\"]\n"
            "!call[api=posts;payload=\"{\\\"title\\\":\\\"Hello World\\\",\\\"author\\\":\\\"Alice\\\"}\"]\n",
            // Verbose JSON
            "{\n"
            "  \"version\": \"LLM-TOPv1\",\n"
            "  \"checksum\": \"sha256:789a\",\n"
            "  \"agent\": \"synth\",\n"
            "  \"uid\": \"anon\",\n"
            "  \"time\": \"2026-07-18\",\n"
            "  \"reqid\": \"req_synth\",\n"
            "  \"fallback\": \"json\",\n"
            "  \"statements\": [\n"
            "    {\n"
            "      \"role\": \"SYNTH\",\n"
            "      \"kvpairs\": {\n"
            "        \"tgt\": \"pipeline\",\n"
            "        \"act\": \"test\",\n"
            "        \"GL\": \"load_test\",\n"
            "        \"TD\": \"generate_data\"\n"
            "      },\n"
            "      \"commands\": [\n"
            "        { \"tool\": \"call\", \"args\": { \"api\": \"auth\", \"payload\": \"{\\\"user\\\":\\\"test_user\\\",\\\"token\\\":\\\"temp_token_123\\\"}\" } },\n"
            "        { \"tool\": \"call\", \"args\": { \"api\": \"users\", \"payload\": \"{\\\"action\\\":\\\"create\\\",\\\"name\\\":\\\"Alice\\\"}\" } },\n"
            "        { \"tool\": \"call\", \"args\": { \"api\": \"posts\", \"payload\": \"{\\\"title\\\":\\\"Hello World\\\",\\\"author\\\":\\\"Alice\\\"}\" } }\n"
            "      ]\n"
            "    }\n"
            "  ]\n"
            "}",
            // Minimal JSON
            "{\"v\":\"LLM-TOPv1\",\"c\":\"sha256:789a\",\"a\":\"synth\",\"u\":\"anon\",\"t\":\"2026-07-18\",\"r\":\"req_synth\",\"f\":\"json\",\"s\":[{\"o\":\"SYNTH\",\"k\":{\"t\":\"pipeline\",\"a\":\"test\",\"G\":\"load_test\",\"T\":\"generate_data\"},\"c\":[{\"t\":\"call\",\"a\":{\"a\":\"auth\",\"p\":\"{\\\"user\\\":\\\"test_user\\\",\\\"token\\\":\\\"temp_token_123\\\"}\"}},{\"t\":\"call\",\"a\":{\"a\":\"users\",\"p\":\"{\\\"action\\\":\\\"create\\\",\\\"name\\\":\\\"Alice\\\"}\"}},{\"t\":\"call\",\"a\":{\"a\":\"posts\",\"p\":\"{\\\"title\\\":\\\"Hello World\\\",\\\"author\\\":\\\"Alice\\\"}\"}}]}]}",
            // Compact JSON
            "{\"version\":\"LLM-TOPv1\",\"checksum\":\"sha256:789a\",\"agent\":\"synth\",\"uid\":\"anon\",\"time\":\"2026-07-18\",\"reqid\":\"req_synth\",\"fallback\":\"json\",\"statements\":[{\"role\":\"SYNTH\",\"kvpairs\":{\"tgt\":\"pipeline\",\"act\":\"test\",\"GL\":\"load_test\",\"TD\":\"generate_data\"},\"commands\":[{\"tool\":\"call\",\"args\":{\"api\":\"auth\",\"payload\":\"{\\\"user\\\":\\\"test_user\\\",\\\"token\\\":\\\"temp_token_123\\\"}\"}},{\"tool\":\"call\",\"args\":{\"api\":\"users\",\"payload\":\"{\\\"action\\\":\\\"create\\\",\\\"name\\\":\\\"Alice\\\"}\"}},{\"tool\":\"call\",\"args\":{\"api\":\"posts\",\"payload\":\"{\\\"title\\\":\\\"Hello World\\\",\\\"author\\\":\\\"Alice\\\"}\"}}]}]}",
            // YAML
            "version: LLM-TOPv1\n"
            "checksum: sha256:789a\n"
            "agent: synth\n"
            "uid: anon\n"
            "time: 2026-07-18\n"
            "reqid: req_synth\n"
            "fallback: json\n"
            "statements:\n"
            "  - role: SYNTH\n"
            "    kvpairs:\n"
            "      tgt: pipeline\n"
            "      act: test\n"
            "      GL: load_test\n"
            "      TD: generate_data\n"
            "    commands:\n"
            "      - tool: call\n"
            "        args:\n"
            "          api: auth\n"
            "          payload: '{\"user\":\"test_user\",\"token\":\"temp_token_123\"}'\n"
            "      - tool: call\n"
            "        args:\n"
            "          api: users\n"
            "          payload: '{\"action\":\"create\",\"name\":\"Alice\"}'\n"
            "      - tool: call\n"
            "        args:\n"
            "          api: posts\n"
            "          payload: '{\"title\":\"Hello World\",\"author\":\"Alice\"}'\n"
        }
    };

    std::cout << "===============================================================\n";
    std::cout << "               REAL-WORLD TOKEN BENCHMARK\n";
    std::cout << "===============================================================\n\n";

    std::vector<float> top_vs_verbose_savings;
    std::vector<float> top_vs_minimal_savings;
    std::vector<float> top_vs_compact_savings;
    std::vector<float> top_vs_yaml_savings;

    std::cout << std::left << std::setw(25) << "Scenario" 
              << std::setw(10) << "LLM-TOP" 
              << std::setw(15) << "Verbose JSON" 
              << std::setw(15) << "Minimal JSON" 
              << std::setw(15) << "Compact JSON" 
              << "YAML\n";
    std::cout << std::string(85, '-') << "\n";

    for (const auto& s : scenarios) {
        int t_top = estimateTokens(s.top);
        int t_verb = estimateTokens(s.verbose_json);
        int t_min = estimateTokens(s.minimal_json);
        int t_comp = estimateTokens(s.compact_json);
        int t_yaml = estimateTokens(s.yaml);

        float s_verb = 100.0f * (1.0f - (float)t_top / t_verb);
        float s_min = 100.0f * (1.0f - (float)t_top / t_min);
        float s_comp = 100.0f * (1.0f - (float)t_top / t_comp);
        float s_yaml = 100.0f * (1.0f - (float)t_top / t_yaml);

        top_vs_verbose_savings.push_back(s_verb);
        top_vs_minimal_savings.push_back(s_min);
        top_vs_compact_savings.push_back(s_comp);
        top_vs_yaml_savings.push_back(s_yaml);

        std::cout << std::left << std::setw(25) << s.name 
                  << std::setw(10) << t_top 
                  << std::setw(15) << (std::to_string(t_verb) + " (" + std::to_string((int)s_verb) + "%)")
                  << std::setw(15) << (std::to_string(t_min) + " (" + std::to_string((int)s_min) + "%)")
                  << std::setw(15) << (std::to_string(t_comp) + " (" + std::to_string((int)s_comp) + "%)")
                  << std::to_string(t_yaml) + " (" + std::to_string((int)s_yaml) + "%)\n";
    }

    auto get_median_and_range = [](std::vector<float> savings) -> std::string {
        std::sort(savings.begin(), savings.end());
        float median = savings[2];
        float min_val = savings.front();
        float max_val = savings.back();
        std::stringstream ss;
        ss << std::fixed << std::setprecision(1) << median << "% (range: " << min_val << "% to " << max_val << "%)";
        return ss.str();
    };

    std::cout << std::string(85, '-') << "\n";
    std::cout << "SUMMARY OF SAVINGS (Token reduction by using LLM-TOP):\n";
    std::cout << "  vs Verbose JSON: " << get_median_and_range(top_vs_verbose_savings) << "\n";
    std::cout << "  vs Compact JSON: " << get_median_and_range(top_vs_compact_savings) << "\n";
    std::cout << "  vs Minimal JSON: " << get_median_and_range(top_vs_minimal_savings) << "\n";
    std::cout << "  vs YAML:         " << get_median_and_range(top_vs_yaml_savings) << "\n";
    std::cout << std::string(85, '=') << "\n";

    return 0;
}
