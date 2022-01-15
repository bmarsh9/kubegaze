import uuid

def generate_uuid(length=None):
    id = uuid.uuid4().hex
    if length:
        id = id[:length]
    return id

def get_table_object(table=None):
    if table is None:
        return current_app.models
    return current_app.models.get(table.lower())

def msg_to_json(message="None",result=False,label="warning",**kwargs):
    '''
    .Description --> Return JSON message for the result
    '''
    message = {
        "message":str(message),
        "result":result,
        "type":str(label),
        "id":kwargs.get("id")
    }
    return message

def get_TableSchema(table,column=None,is_date=False,is_int=False,is_str=False,is_json=False,is_bool=False):
    '''
    :Description - Get a tables col names and types Usage - ("table",column="message",is_str=True)
    '''
    data = {}
    for col in table.__table__.columns:
        try: # field type JSON does not have a type attribute
            col_type=str(col.type)
        except:
            col_type="JSON"
        data[col.name] = str(col_type)
    if column is not None:
        splice = data.get(column,None)
        if splice:
            if is_int and "INTEGER" in splice:
                return True
            if is_str and "VARCHAR" in splice:
                return True
            if is_json and "JSON" in splice:
                return True
            if is_bool and "BOOLEAN" in splice:
                return True
            if is_date and "DATETIME" in splice:
                return True
            return False
        raise Exception("Column not found")
    return data
