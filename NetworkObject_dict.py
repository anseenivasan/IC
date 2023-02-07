





##Reading a file





def object_network(f):
    d ={}
    for lnum, line in enumerate(f):

        ## updating the dictionary values for all the object network

        if line.startswith('object network'):
            key1 = line.split()[-1]

            d[key1] = {'subnet': [], 'host': [], 'range': []}
            continue

        if line.startswith(' subnet'):
            value = line.strip(' ').split('subnet ')[-1].strip()

            d[key1]['subnet'].append(value)
        if line.startswith(' host'):
            value = line.strip(' ').split('host ')[-1].strip()
            d[key1]['host'].append(value)
        if line.startswith(' range'):
            value = line.strip(' ').split('range ')[-1].strip()
            d[key1]['range'].append(value)

    return d





