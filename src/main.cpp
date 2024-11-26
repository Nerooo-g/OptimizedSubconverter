#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <crow.h>
#include <yaml-cpp/yaml.h>
#include <iostream>
#include <fstream>
#include <regex>
#include "httplib.h" // For HTTP requests


std::string urlDecode(const std::string &url) {
    std::string decoded;
    int ii;
    for (std::string::size_type i = 0; i < url.length(); i++) {
        if (url[i] == '%') {
            if (i + 2 < url.length()) {
                if (std::istringstream iss(url.substr(i + 1, 2)); iss >> std::hex >> ii) {
                    const char ch = static_cast<char>(ii);
                    decoded += ch;
                    i += 2;
                }
            }
        } else if (url[i] == '+') {
            decoded += ' ';
        } else {
            decoded += url[i];
        }
    }
    return decoded;
}

int main() {
    // std::getenv("");
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")
    .methods("GET"_method)
    ([&](const crow::request& req) {
        auto query_params = crow::query_string(req.url_params);

        std::string param = query_params.get("sub") ? query_params.get("sub") : "";
        std::string name = query_params.get("name") ? query_params.get("name") : "Subscription";
        std::string pvd=query_params.get("pvd") ? query_params.get("pvd") : "";
        std::string meta=query_params.get("meta") ? query_params.get("meta") : "false";
        std::string dns = query_params.get("dns") ? query_params.get("dns") : "false";
        if (meta != "true" && meta != "false") {
            std::cerr << "Invalid meta value. It must be true or false." << std::endl;
            return crow::response(500, "Invalid meta value. It must be true or false.");
        }
        if (dns != "true" && dns != "false") {
            std::cerr << "Invalid dns value. It must be true or false." << std::endl;
            return crow::response(500, "Invalid dns value. It must be true or false.");
        }

        // Sanitize the filename to ensure it's safe and compatible
        std::regex pattern("[^a-zA-Z0-9_-]");
        std::string safe_name = std::regex_replace(name, pattern, "_");

        // Load YAML data from file
        YAML::Node yaml_data;
        try {
            yaml_data = YAML::LoadFile("../config.yaml");
        } catch (const std::exception& e) {
            std::cerr << "Failed to load config.yaml: " << e.what() << std::endl;
            return crow::response(500, "Failed to load config.yaml"+std::string(e.what()));
        }
        if (meta == "true") {
            yaml_data["geodata-mode"]=true;
            yaml_data["geo-auto-update"]=true;
            yaml_data["geo-update-interval"]=24;
            yaml_data["geox-url"]=YAML::Node(YAML::NodeType::Map);
            yaml_data["geox-url"]["geoip"]="https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat";
            yaml_data["geox-url"]["geosite"]="https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";
            yaml_data["geox-url"]["mmdb"]="https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country-without-asn.mmdb";
            yaml_data["geox-url"]["asn"]="https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb";
        }

        if (meta=="true" && dns=="true") {
            YAML::Node dns_data;
            try {
                dns_data=YAML::LoadFile("../dns.yaml");
            } catch (const std::exception& e) {
                std::cerr << "Failed to load dns.yaml: " << e.what() << std::endl;
                return crow::response(500, "Failed to load dns.yaml"+std::string(e.what()));
            }
            const std::string domesticNameservers[]={"https://dns.alidns.com/dns-query","https://doh.pub/dns-query"};
            const std::string foreignNameservers[] = {"https://1.1.1.1/dns-query",  "https://1.0.0.1/dns-query",
                "https://208.67.222.222/dns-query", "https://208.67.220.220/dns-query",
                "https://194.242.2.2/dns-query", "https://194.242.2.3/dns-query"};
            dns_data["nameserver"]=YAML::Node(YAML::NodeType::Sequence);
            dns_data["proxy-server-nameserver"]=YAML::Node(YAML::NodeType::Sequence);
            dns_data["nameserver-policy"]=YAML::Node(YAML::NodeType::Map);
            dns_data["nameserver-policy"]["geosite:private,cn,geolocation-cn"]=YAML::Node(YAML::NodeType::Sequence);
            dns_data["nameserver-policy"]["geosite:google,youtube,telegram,gfw,geolocation-!cn:"]=
                YAML::Node(YAML::NodeType::Sequence);
            for (const auto& it : domesticNameservers) {
                dns_data["nameserver"].push_back(it);
                dns_data["proxy-server-nameserver"].push_back(it);
                dns_data["nameserver-policy"]["geosite:private,cn,geolocation-cn"].push_back(it);
            }
            for (const auto& it : foreignNameservers) {
                dns_data["nameserver"].push_back(it);
                dns_data["proxy-server-nameserver"].push_back(it);
                dns_data["nameserver-policy"]["geosite:google,youtube,telegram,gfw,geolocation-!cn:"].push_back(it);
            }
            yaml_data["dns"]=dns_data["dns"];
        }

        // Update the YAML data with provided parameters

        yaml_data["proxy-providers"][safe_name] = YAML::Node();
        yaml_data["proxy-providers"][safe_name]["type"] = "http";
        if (pvd.empty()) {
            yaml_data["proxy-providers"][safe_name]["url"] = param;
        } else {
            pvd=urlDecode(pvd);
            yaml_data["proxy-providers"][safe_name]["url"] = pvd;
        }
        yaml_data["proxy-providers"][safe_name]["interval"] = 86400;

        // Create the sequence of maps for proxy-name patterns
        auto proxy_name_patterns = YAML::Node(YAML::NodeType::Sequence);

        // Create and add each pattern-target map to the sequence
        {
            auto pattern_node = YAML::Node(YAML::NodeType::Map);
            pattern_node["pattern"] = "^(?!.*🇭🇰)(.*)(港|HK|(?i)Hong)(.*)";
            pattern_node["target"] = "🇭🇰 $1$2$3";
            proxy_name_patterns.push_back(pattern_node);
        }

        {
            auto pattern_node = YAML::Node(YAML::NodeType::Map);
            pattern_node["pattern"] = "^(🇨🇳|🇹🇼)?(.*(台|TW|(?i)Taiwan|新北|彰化).*)(🇨🇳|🇹🇼)?(.*)$";
            pattern_node["target"] = "🇹🇼 $2$5";
            proxy_name_patterns.push_back(pattern_node);
        }

        {
            auto pattern_node = YAML::Node(YAML::NodeType::Map);
            pattern_node["pattern"] = "^(?!.*🇺🇲)(?!.*🇺🇸)(.*)(美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|"
                                      "圣克拉拉|西雅图|芝加哥|US|(?i)United States)(.*)";
            pattern_node["target"] = "🇺🇸 $1$2$3";
            proxy_name_patterns.push_back(pattern_node);
        }

        {
            auto pattern_node = YAML::Node(YAML::NodeType::Map);
            pattern_node["pattern"] = "^(?!.*🇯🇵)(.*)(日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|(?i)Japan)(.*)";
            pattern_node["target"] = "🇯🇵 $1$2$3";
            proxy_name_patterns.push_back(pattern_node);
        }

        {
            auto pattern_node = YAML::Node(YAML::NodeType::Map);
            pattern_node["pattern"] = "^(?!.*🇸🇬)(.*)(新加坡|坡|狮城|SG|(?i)Singapore)(.*)";
            pattern_node["target"] = "🇸🇬 $1$2$3";
            proxy_name_patterns.push_back(pattern_node);
        }

        // Assign the sequence to the override node
        yaml_data["proxy-providers"][safe_name]["override"]["proxy-name"] = proxy_name_patterns;

        yaml_data["proxy-providers"][safe_name]["exclude-filter"] = "到期|剩余流量|时间|官网|产品|平台|Traffic|Expire";

        // Convert the updated data to YAML format
        std::stringstream yaml_stream;
        yaml_stream << yaml_data;
        std::regex url_regex(R"(^(https?)://([^/]+)(/.*)?$)");
        std::string subscription_userinfo = "None";
        param=urlDecode(param);

        if (std::smatch url_match_result; std::regex_match(param, url_match_result, url_regex)) {
            std::string protocol = url_match_result[1].str(); // http or https
            std::string host = url_match_result[2].str();     // host name
            std::string path = url_match_result[3].str();     // path + query

            //cout all params
            // std::cout<<"protocol: "<<protocol<<" path: "<<path<<std::endl;
            // std::cout<<"host: "<<host<<" path: "<<path<<std::endl;
            // std::cout<<"path: "<<path<<std::endl;

            if (path.empty()) {
                path = "/";
            }
            // 根据协议选择客户端构造
            httplib::Client cli(protocol+"://"+host);
            if (protocol == "https") {
                cli.enable_server_certificate_verification(false); // 如果有自签名证书或开发测试环境，请禁用检验证书
            }
            if (auto res = cli.Head(path)) {
                if (res->has_header("subscription-userinfo")) {
                    subscription_userinfo = res->get_header_value("subscription-userinfo");
                }
                std::cout << "The subscription-userinfo is: " << subscription_userinfo << std::endl;
            }
            else {
                std::cout << "Request failed. Error code: " << res.error() << std::endl;
            }
        }
        else {
            std::cout << "Invalid URL: " << param << std::endl;
        }

        // Create response
        crow::response response;
        response.set_header("Content-Type", "application/x-yaml");
        response.set_header("Content-Disposition", "attachment; filename=" + safe_name);
        response.set_header("subscription-userinfo", subscription_userinfo);
        response.body = yaml_stream.str();
        return response;
    });

    app.port(1927).multithreaded().run();
}
