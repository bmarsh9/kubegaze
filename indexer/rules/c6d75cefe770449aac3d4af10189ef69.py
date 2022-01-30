def uuid_c6d75cefe770449aac3d4af10189ef69(event, **kwargs):
    '''Place your custom code below.
    Must be indented under this function.'''
    results = {'hit': False, 'evidence': '', 'rule_id': 10}

    results["hit"] = True
    results["evidence"] = "testing"
    '''If you want the rule to match the event,
    be sure to set the "hit" key to True in the results dict'''
    return results
    