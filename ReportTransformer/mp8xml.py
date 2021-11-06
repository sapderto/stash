# import xml.etree.ElementTree as XML
import xml.dom.minidom as XML


def has_value(variable, placeholder):
    if variable:
        return variable
    else:
        return placeholder


def has_first_child(variable, placeholder):
    if variable:
        if variable[0]:
            if variable[0].firstChild:
                return variable[0].firstChild.nodeValue
            else:
                return placeholder
        else:
            return placeholder
    else:
        return placeholder


def process_report(filename, **kwargs):
    critical_level = kwargs['critical_value'] if 'critical_value' in kwargs else 0
    placeholder = kwargs['placeholder'] if 'placeholder' in kwargs else ""
    result = {}
    # Сбор базы уязвимосей
    vulners_base = {}
    vulner_index = 0
    try:
        doc_model = XML.parse(filename)
        doc_model.normalize()

        vulners_tags = [vu for vu in [v for v in doc_model.getElementsByTagName("content")[0].childNodes if
                                      v.localName == 'vulners'][0].childNodes if vu.localName == 'vulner']
        for vulner in vulners_tags:
            if vulner.getElementsByTagName('cvss'):
                cvss_tmp = vulner.getElementsByTagName('cvss')[0]
                cvss_temp_score = has_value(cvss_tmp.getAttribute('temp_score'), "")
                cvss_base_score = has_value(cvss_tmp.getAttribute('base_score'), "")
                cvss_temp_score_decomp = has_value(cvss_tmp.getAttribute('temp_score_decomp'), "")
                cvss_base_score_decomp = has_value(cvss_tmp.getAttribute('base_score_decomp'), "")
            else:
                cvss_temp_score = ""
                cvss_base_score = ""
                cvss_temp_score_decomp = ""
                cvss_base_score_decomp = ""
            if vulner.getElementsByTagName('cvss3'):
                cvss3_tmp = vulner.getElementsByTagName('cvss3')[0]
                cvss3_temp_score = has_value(cvss3_tmp.getAttribute('temp_score'), "")
                cvss3_base_score = has_value(cvss3_tmp.getAttribute('base_score'), "")
                cvss3_temp_score_decomp = has_value(cvss3_tmp.getAttribute('temp_score_decomp'), "")
                cvss3_base_score_decomp = has_value(cvss3_tmp.getAttribute('base_score_decomp'), "")
            else:
                cvss3_temp_score = ""
                cvss3_base_score = ""
                cvss3_temp_score_decomp = ""
                cvss3_base_score_decomp = ""
            vulners_base[vulner.getAttribute('id')] = {
                "title": has_first_child(vulner.getElementsByTagName("title"), ""),
                "short_description": has_first_child(vulner.getElementsByTagName("short_desctiption"), ""),
                "description": has_first_child(vulner.getElementsByTagName("description"), ""),
                "how_to_fix": has_first_child(vulner.getElementsByTagName("how_to_fix"), ""),
                "links": has_first_child(vulner.getElementsByTagName("links"), ""),
                "publication_date": has_first_child(vulner.getElementsByTagName("publication_date"), ""),
                "cvss_temp_score": cvss_temp_score,
                "cvss_base_score": cvss_base_score,
                "cvss_temp_score_decomp": cvss_temp_score_decomp,
                "cvss_base_score_decomp": cvss_base_score_decomp,
                "cvss3_temp_score": cvss3_temp_score,
                "cvss3_base_score": cvss3_base_score,
                "cvss3_temp_score_decomp": cvss3_temp_score_decomp,
                "cvss3_base_score_decomp": cvss3_base_score_decomp
            }
            vulner_identificators = has_value(vulner.getElementsByTagName("global_id"), False)
            if vulner_identificators:
                BID = []
                CVE = []
                OSVDB = []
                fstec = []
                for tag in vulner_identificators:
                    if tag.getAttribute("name") == "BID":
                        BID.append(tag.getAttribute("value"))
                    elif tag.getAttribute("name") == "CVE":
                        CVE.append(tag.getAttribute("value"))
                    elif tag.getAttribute("name") == "fstec":
                        fstec.append(tag.getAttribute("value"))
                    elif tag.getAttribute("name") == "OSVDB":
                        fstec.append(tag.getAttribute("value"))
                    else:
                        print("Unprocessable global_id:", tag.getAttribute("name"), tag.getAttribute("value"))
                if BID:
                    vulners_base[vulner.getAttribute('id')]["vulner_bid"] = "\n".join(BID)
                else:
                    vulners_base[vulner.getAttribute('id')]["vulner_bid"] = ''
                if CVE:
                    vulners_base[vulner.getAttribute('id')]["vulner_cve"] = "\n".join(CVE)
                else:
                    vulners_base[vulner.getAttribute('id')]["vulner_cve"] = ''
                if fstec:
                    vulners_base[vulner.getAttribute('id')]["vulner_fstec"] = "\n".join(fstec)
                else:
                    vulners_base[vulner.getAttribute('id')]["vulner_fstec"] = ''
                if OSVDB:
                    vulners_base[vulner.getAttribute('id')]["vulner_osvdb"] = "\n".join(OSVDB)
                else:
                    vulners_base[vulner.getAttribute('id')]["vulner_osvdb"] = ''
        # Сбор информации о хостах
        host_tags = doc_model.getElementsByTagName("host")
        for host in host_tags:
            host_ip = has_value(host.getAttribute('ip'), placeholder)
            host_fqdn = has_value(host.getAttribute('fqdn'), placeholder)
            host_start_scan = has_value(host.getAttribute('start_time'), placeholder)
            host_stop_scan = has_value(host.getAttribute('stop_time'), placeholder)
            for scan_objects in host.getElementsByTagName("scan_objects")[0].getElementsByTagName("soft"):
                name_tage = scan_objects.getElementsByTagName("name")[0].firstChild
                soft_version = scan_objects.getElementsByTagName("version")
                soft_version = soft_version[0].firstChild.nodeValue if soft_version[0] and soft_version[
                    0].firstChild is not None else ""
                vulners_tage = scan_objects.getElementsByTagName("vulners")
                if name_tage and vulners_tage:
                    # name_tage.nodeValue - имя источника ПО
                    for vulner in vulners_tage[0].getElementsByTagName("vulner"):
                        if int(vulner.getAttribute('level')) >= critical_level:
                            result[vulner_index] = {'host_ip': host_ip, 'host_fqdn': host_fqdn,
                                                    'source': name_tage.nodeValue,
                                                    'version': soft_version,
                                                    'level': vulner.getAttribute('level'),
                                                    'vulner_id': vulner.getAttribute('id'),
                                                    'status': vulner.getAttribute('status'),
                                                    "host_start_scan": host_start_scan,
                                                    'host_stop_scan': host_stop_scan,
                                                    'vulner_title': vulners_base[vulner.getAttribute('id')]['title']
                                                    }
                            vulner_index += 1

        for vulner_state in result:
            if result[vulner_state]['vulner_id'] and result[vulner_state]['vulner_id'] in vulners_base:
                result[vulner_state].update(vulners_base[result[vulner_state]['vulner_id']])
    except PermissionError:
        result['status'] = "warning"
        result['status_cause'] = f"Permission problems with file {filename}"
    except FileNotFoundError:
        result['status'] = "warning"
        result['status_cause'] = f"File {filename} is not found"
    except BaseException as e:
        result['status'] = 'error'
        result['status_cause'] = str(e)
    finally:
        return result

# if __name__ == "__main__":
# finish = process_report("test.xml", critical_value=3)
# for e in finish:
#    print(e, finish[e])
