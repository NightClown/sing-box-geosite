import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress

# 映射字典
MAP_DICT = {'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
            'DOMAIN-KEYWORD':'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
            'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 
            'IP6-CIDR': 'ip_cidr','SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
            'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"}

def read_yaml_from_url(url):
    response = requests.get(url)
    response.raise_for_status()
    yaml_data = yaml.safe_load(response.text)
    return yaml_data

def read_list_from_url(url):
    df = pd.read_csv(url, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'])
    filtered_rows = []
    rules = []
    # 处理逻辑规则
    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {
                "type": "logical",
                "mode": "and",
                "rules": []
            }
            pattern = ",".join(row.values.astype(str))
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                for keyword in MAP_DICT.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({
                                MAP_DICT[keyword]: value
                            })
            rules.append(rule)
    # for index, row in df.iterrows():
    #     if 'AND' not in row['pattern']:
    #         row['pattern'].strip()
    #         row['address'].strip()
    #         filtered_rows.append(row)
    filtered_df = df[~df['pattern'].str.contains('AND')]

    # Stripping whitespace from 'pattern' and 'address' columns
    filtered_df['pattern'] = filtered_df['pattern'].str.strip()
    filtered_df['address'] = filtered_df['address'].str.strip()

    # If you need the result as a list of rows, you can use .to_dict(orient='records')
    filtered_rows = filtered_df.to_dict(orient='records')
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    rules = []
    # 根据链接扩展名分情况处理
    if link.endswith('.yaml') or link.endswith('.txt'):
        try:
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                line_content = lines[0]
                items = line_content.split()
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address[1:]
                            if address.startswith('.'):
                                address = address[1:]
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)
                if pattern in ("IP-CIDR", "IP-CIDR6", "IP6-CIDR") and "no-resolve" in address:
                    address = address.split(',', 1)[0]
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        except:
            df, rules = read_list_from_url(link)
    else:
        df, rules = read_list_from_url(link)
    return df, rules

# 对字典进行排序，含list of dict
def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def parse_list_file(link, output_directory):
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results= list(executor.map(parse_and_convert_to_dataframe, [link]))  # 使用executor.map并行处理链接, 得到(df, rules)元组的列表
            dfs = [df for df, rules in results]   # 提取df的内容
            rules_list = [rules for df, rules in results]  # 提取逻辑规则rules的内容
            df = pd.concat(dfs, ignore_index=True)  # 拼接为一个DataFrame
        df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)  # 删除pattern中包含#号的行
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)  # 删除不在字典中的pattern
        df = df.drop_duplicates().reset_index(drop=True)  # 删除重复行
        df['pattern'] = df['pattern'].replace(MAP_DICT)  # 替换pattern为字典中的值
        os.makedirs(output_directory, exist_ok=True)  # 创建自定义文件夹

        result_rules = {"version": 1, "rules": []}
        domain_entries = []
        for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
            if pattern == 'domain_suffix':
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
                # domain_entries.extend([address.strip() for address in addresses])  # 1.9以下的版本需要额外处理 domain_suffix
            elif pattern == 'domain':
                domain_entries.extend([address.strip() for address in addresses])
            else:
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
        # 删除 'domain_entries' 中的重复值
        domain_entries = list(set(domain_entries))
        if domain_entries:
            result_rules["rules"].insert(0, {'domain': domain_entries})

        # 处理逻辑规则
        """
        if rules_list[0] != "[]":
            result_rules["rules"].extend(rules_list[0])
        """

        # 使用 output_directory 拼接完整路径
        file_name = os.path.join(output_directory, f"{os.path.basename(link).split('.')[0]}.json")
        with open(file_name, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')
            output_file.write(result_rules_str)

        srs_path = file_name.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
        return file_name
    except:
        print(f'获取链接出错，已跳过：{link}')
        pass

def generate_srs_by_json():
    # 获取rule目录下所有的json文件
    json_files = [f for f in os.listdir("./rule") if f.endswith('.json')]
    
    for json_file in json_files:
        json_path = os.path.join("./rule", json_file)
        srs_path = json_path.replace(".json", ".srs")
        
        # 检查对应的.srs文件是否存在
        if not os.path.exists(srs_path):
            try:
                # 使用sing-box命令生成.srs文件
                os.system(f"sing-box rule-set compile --output {srs_path} {json_path}")
                print(f"Generated {srs_path}")
            except Exception as e:
                print(f"Error generating {srs_path}: {str(e)}")


def parse_ruleset_line(line):
    """解析 ruleset= 格式的行，返回 (group_name, clash_type, url, no_resolve)"""
    # 格式: ruleset=🔍 Google,clash-classic:https://...
    # 或:   ruleset=🔍 Google,clash-ipcidr:https://...,no-resolve
    line = line.strip()
    if not line.startswith("ruleset="):
        return None
    content = line[len("ruleset="):]
    # 提取组名（emoji + 名称部分）
    # 格式: 🔍 Google,clash-type:url
    parts = content.split(",", 1)
    if len(parts) < 2:
        return None
    group_tag = parts[0].strip()  # e.g. "🔍 Google"
    rest = parts[1].strip()       # e.g. "clash-classic:https://...,no-resolve"

    # 提取 clash type 和 URL
    type_url = rest.split(":", 1)
    if len(type_url) < 2:
        return None
    clash_type = type_url[0].strip()  # e.g. "clash-classic"
    url_part = type_url[1].strip()    # e.g. "https://..."

    # 处理 URL（可能包含 ,no-resolve 后缀）
    no_resolve = False
    if url_part.endswith(",no-resolve"):
        no_resolve = True
        url_part = url_part[:-len(",no-resolve")]

    # 从组名中提取简短名称（去掉 emoji 前缀）
    # e.g. "🔍 Google" -> "Google", "🌟 Gemini" -> "Gemini"
    name_parts = group_tag.split(" ", 1)
    group_name = name_parts[-1].strip() if len(name_parts) > 1 else group_tag

    return (group_name, clash_type, url_part, no_resolve)


def parse_ruleset_group(group_name, entries, output_directory):
    """将多个 ruleset 条目合并为一个 JSON/SRS 文件
    entries: list of (clash_type, url, no_resolve)
    """
    try:
        all_domains = []
        all_domain_suffixes = []
        all_domain_keywords = []
        all_ip_cidrs = []
        all_domain_regexes = []
        all_other_rules = {}  # key -> list of values

        for clash_type, url, no_resolve in entries:
            print(f"  Fetching: {url}")
            try:
                if clash_type in ("clash-domain", "clash-ipcidr"):
                    # YAML payload 格式
                    yaml_data = read_yaml_from_url(url)
                    if isinstance(yaml_data, dict):
                        items = yaml_data.get('payload', [])
                    else:
                        items = []

                    for item in items:
                        address = str(item).strip().strip("'")
                        if clash_type == "clash-ipcidr":
                            all_ip_cidrs.append(address)
                        elif clash_type == "clash-domain":
                            if address.startswith('+.') or address.startswith('.'):
                                suffix = address.lstrip('+').lstrip('.')
                                all_domain_suffixes.append(suffix)
                            else:
                                all_domains.append(address)

                elif clash_type == "clash-classic":
                    # 经典 Clash 规则格式（可能是 YAML 或 list）
                    df, rules = parse_and_convert_to_dataframe(url)
                    # 过滤无效行
                    df = df[~df['pattern'].str.contains('#', na=False)].reset_index(drop=True)
                    df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
                    df['pattern'] = df['pattern'].replace(MAP_DICT)

                    for _, row in df.iterrows():
                        pattern = row['pattern']
                        address = str(row['address']).strip()
                        if pattern == 'domain':
                            all_domains.append(address)
                        elif pattern == 'domain_suffix':
                            all_domain_suffixes.append(address)
                        elif pattern == 'domain_keyword':
                            all_domain_keywords.append(address)
                        elif pattern == 'ip_cidr':
                            all_ip_cidrs.append(address)
                        elif pattern == 'domain_regex':
                            all_domain_regexes.append(address)
                        else:
                            if pattern not in all_other_rules:
                                all_other_rules[pattern] = []
                            all_other_rules[pattern].append(address)

            except Exception as e:
                print(f"  获取链接出错，已跳过：{url} ({e})")
                continue

        # 去重
        all_domains = sorted(set(all_domains))
        all_domain_suffixes = sorted(set(all_domain_suffixes))
        all_domain_keywords = sorted(set(all_domain_keywords))
        all_ip_cidrs = sorted(set(all_ip_cidrs))
        all_domain_regexes = sorted(set(all_domain_regexes))
        for key in all_other_rules:
            all_other_rules[key] = sorted(set(all_other_rules[key]))

        # 构建 sing-box rule-set JSON
        result_rules = {"version": 1, "rules": []}
        if all_domains:
            result_rules["rules"].append({"domain": all_domains})
        if all_domain_suffixes:
            result_rules["rules"].append({"domain_suffix": all_domain_suffixes})
        if all_domain_keywords:
            result_rules["rules"].append({"domain_keyword": all_domain_keywords})
        if all_ip_cidrs:
            result_rules["rules"].append({"ip_cidr": all_ip_cidrs})
        if all_domain_regexes:
            result_rules["rules"].append({"domain_regex": all_domain_regexes})
        for key, values in sorted(all_other_rules.items()):
            result_rules["rules"].append({key: values})

        # 写入 JSON
        os.makedirs(output_directory, exist_ok=True)
        file_name = os.path.join(output_directory, f"{group_name}.json")
        with open(file_name, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')
            output_file.write(result_rules_str)

        # 编译为 .srs
        srs_path = file_name.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
        print(f"Generated {file_name} and {srs_path}")
        return file_name
    except Exception as e:
        print(f"处理规则组 {group_name} 出错：{e}")
        return None


# 读取 links.txt 中的每个链接并生成对应的 JSON 文件
with open(os.path.basename("links.txt"), 'r') as links_file:
    links = links_file.read().splitlines()

links = [l for l in links if l.strip() and not l.strip().startswith("#")]

output_dir = "./rule"
result_file_names = []

# 分离普通链接和 ruleset= 格式的行
regular_links = []
ruleset_groups = {}  # group_name -> list of (clash_type, url, no_resolve)

for line in links:
    parsed = parse_ruleset_line(line)
    if parsed:
        group_name, clash_type, url, no_resolve = parsed
        if group_name not in ruleset_groups:
            ruleset_groups[group_name] = []
        ruleset_groups[group_name].append((clash_type, url, no_resolve))
    else:
        regular_links.append(line)

# 处理普通链接
for link in regular_links:
    result_file_name = parse_list_file(link, output_directory=output_dir)

# 处理 ruleset 分组（合并同名组为一个文件）
for group_name, entries in ruleset_groups.items():
    print(f"Processing ruleset group: {group_name} ({len(entries)} sources)")
    parse_ruleset_group(group_name, entries, output_dir)

# 根据json文件生成srs文件
generate_srs_by_json()
