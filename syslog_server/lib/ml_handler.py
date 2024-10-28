import numpy as np
import pickle
import os
import logging

from syslog_server.lib import data_handler, db_handler

directory = "/var/models"

#Check results against ML models
def ml_check(results, sub_results, pfsense_instance, filename):
    result = [results[0], pfsense_instance, results[3], sub_results[0], sub_results[1], sub_results[2], sub_results[3], sub_results[4], sub_results[5], sub_results[6], sub_results[7], sub_results[8], sub_results[14], sub_results[16], sub_results[18], sub_results[19], sub_results[21]]
    new_result = []
    for item in result:
        new_result = data_handler.row_sanitize(item, new_result)
    new_result = np.array([new_result])
    hostname_query = "SELECT hostname FROM pfsense_instances WHERE id = {}"
    hostname = db_handler.query_db(hostname_query.format(pfsense_instance))[0][0]
    daily_model_location = os.path.join(directory + "/" + hostname)
    model = pickle.load(open(daily_model_location + "/" + filename + ".pickle", 'rb'))
    prediction = model.predict(new_result)[0]
    return(prediction)

def ml_process(results, sub_results, pfsense_instance, filename):
        try:
            ml_result = ml_check(results, sub_results, pfsense_instance, filename)
        except Exception:
            logging.exception("Error when running ml_process")
            ml_result = "'NULL'"
        return(ml_result)
