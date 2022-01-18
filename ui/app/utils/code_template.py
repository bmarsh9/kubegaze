import os
from flask import current_app

'''
Note: end-user can NOT edit the first three or the last three lines.
Any comments or code placed in those lines can't be changed by end user
'''

def default_rule_code(name="code"):
    return """def uuid_{}(event, **kwargs):
    '''Place your custom code below.
    Must be indented under this function.'''
    results = {}


    '''If you want the rule to match the event,
    be sure to set the "hit" key to True in the results dict'''
    return results
    """.format(name,{"hit":False,"evidence":""})
