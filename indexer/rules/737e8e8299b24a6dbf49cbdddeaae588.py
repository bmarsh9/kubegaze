def uuid_737e8e8299b24a6dbf49cbdddeaae588(event, **kwargs):
    '''Place your custom code below.
    Must be indented under this function.'''
    results = {'hit': False, 'evidence': '', 'rule_id': 8}


    results["hit"] = True
    results["evidence"] = '{"test":"testing"}'
    '''If you want the rule to match the event,
    be sure to set the "hit" key to True in the results dict'''
    return results
    