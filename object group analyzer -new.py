
from ipaddress import IPv4Address, IPv4Network, summarize_address_range
from collections import defaultdict
import optparse
import re



class log_color(object):
    """ Used for bash coloring... """
    @classmethod
    def red(cls, text):
        return '\x1b[91m%s\x1b[0m' % (text)

    @classmethod
    def blue(cls, text):
        return '\x1b[34m%s\x1b[0m' % (text)

    @classmethod
    def green(cls, text):
        return '\x1b[32m%s\x1b[0m' % (text)

    @classmethod
    def yellow(cls, text):
        return '\x1b[33m%s\x1b[0m' % (text)

    @classmethod
    def magenta(cls, text):
        return '\x1b[35m%s\x1b[0m' % (text)

class Segment(object):
    # Used to contain a segement (of ints)
    l = None
    r = None

    def __init__(self, l, r):
        self.l = l
        self.r = r
        assert self.r >= self.l
    def __repr__(self):
        return "Segement(%s, %s)" % (self.l, self.r)
    def __lt__(self, other):
        return other.l > self.l

def build_object_groups_fromacl(cfg,group_dict,ignore_non_contig=False):
    pattern_regex = re.compile(r'access-list \w* \w* (permit|deny|trust) (object-group \w*|\w*)? (object-group '
                               r'\w*|any|host \d+.\d+.\d+.\d+|\d+.\d+.\d+.\d+ \d+.\d+.\d+.\d+|object [\w.-]*)? '
                               r'(object-group \w*|any|host \d+.\d+.\d+.\d+|\d+.\d+.\d+.\d+ \d+.\d+.\d+.\d+)?')

    srclist = defaultdict(set)
    dstlist = defaultdict(set)
    src_objectgroup = []
    dst_objectgroup = []

    print((group_dict)['FMC_INLINE_src_rule_268449335'])

    for lnum, line in enumerate(cfg):

        if pattern_regex.search(line) != None:
            pattern = pattern_regex.search(line)
            src_objectgroup = pattern.group(3)
            dst_objectgroup = pattern.group(4)



            # print(line.strip())
            # print(src_objectgroup)

            if 'object-group' in src_objectgroup:


                new_src_objectgroup = src_objectgroup.replace('object-group', '')

                srclist[new_src_objectgroup.strip()].update(group_dict[new_src_objectgroup.strip()])

            if dst_objectgroup is not None :
                if 'object-group' in dst_objectgroup:

                    new_dst_objectgroup = dst_objectgroup.replace('object-group', '')
                    dstlist[new_dst_objectgroup.strip()].update(group_dict[new_dst_objectgroup.strip()])
                else:
                    continue





            # new_dst_objectgroup = dst_objectgroup.replace('object-group', '')
            # dstlist[new_dst_objectgroup.strip()].update(group_dict[new_dst_objectgroup.strip()]

        else:
            continue




    print('test {0}'.format(dst_objectgroup))
    return(srclist,dstlist)

def build_object_groups(cfg, ignore_non_contig=False):
    """ Takes in a list() of lines from an ASA/Lina configuration.
    It proceeds line by line looking for object and object-group definitions.

    Returns a singleton_forward (dict), and group_forward (dict) which map
    an object/singleton name and object-group name to the ipaddress.IPv4Network
    values. There are references to IPv6 objects here, but they are not
    used at this time. """

    name_dict = {}
    singleton_forward = defaultdict(set)
    group_forward = defaultdict(set)
    singleton_reverse = defaultdict(list)
    in_o = None

    # Build forwward lookup for singleton objects
    for l in cfg:
        if l.strip().startswith('name '):
            name_dict[l.split()[2]] = l.split()[1]
    # break out of for loop when the NAt statement in the line seen on the sh tech file
        if l.strip().startswith('nat '):
            break

        if l.strip().startswith('object-group '):
            in_o = None

            continue
        #Take the name of the object network and assign to variable in_o
        if l.strip().startswith('object network '):
            in_o = l.split()[2]

            continue
        if in_o and l.strip().startswith('host '):
            #assign the value of the host in the object network to ip_val
            ip_val = l.strip().split()[-1]


            if ip_val in name_dict:

                ip_val = name_dict[ip_val]

            if ':' in ip_val:

                pass
            else:
            #use the IPV4 network to convert the host value to /32 network.creating a instance of a class called
            # IPv4Network and assigning to ip_data

                ip_data = IPv4Network(ip_val+'/32')






            # singleton_forward[in_o] = set(ip_data)
            singleton_forward[in_o].add(ip_data)
            # print (singleton_forward[in_o])

            singleton_reverse[ip_data].append(in_o)
            # print ((singleton_reverse)[ip_data])



            continue
        if in_o and l.strip().startswith('fqdn '):
            fqdn_data = l.strip().split()[-1]
            singleton_forward[in_o] = set([fqdn_data])
            singleton_reverse[fqdn_data].append(in_o)
            continue
        if in_o and l.strip().startswith('subnet '):
            if ':' in l.split()[-1]:

                pass
            else:
                ip_val = l.split()[-2]

                if ip_val in name_dict:
                    ip_val = name_dict[ip_val]

                try:

                    ip_data = IPv4Network(ip_val+'/'+l.split()[-1])




                except NetmaskValueError:
                    if ignore_non_contig:
                        continue
                    else:
                        raise RuntimeError('Invalid Netmask in Object %s: %s' % (in_o, l))


            singleton_forward[in_o] = set([ip_data])


            singleton_reverse[ip_data].append(in_o)

            continue





        if in_o and l.strip().startswith('range '):
            # The summarize_address_range() function will break the range
            # into a list (iter) of ipaddress.IPv4Network objects
            ip_data = summarize_address_range(IPv4Address(l.split()[-2]),
                                              IPv4Address(l.split()[-1]))

            singleton_forward[in_o] = set(list(ip_data))




            singleton_reverse[l.strip()].append(in_o)





    in_og = None
    for l in cfg:
        if l.strip().startswith('nat '):
            break

        if l.startswith('object-group network '):
            in_og = l.split()[2]
            continue

        if l.startswith('object-group '):
            # This allow us to skip object service object-groups.
            in_og = None
            continue

        if l.startswith('object network '):


            continue

        if in_og and l.strip().startswith('network-object object '):
            net_o = l.strip().split()[-1]


            # fetch the  value of the network object range to update the network-object object

            group_forward[in_og].update(singleton_forward[net_o])





            continue

        if in_og and l.strip().startswith('group-object '):
            grp_o = l.strip().split()[-1]


            # fetch the  value of the group-object(which is referncing other OGN)  to update the group  object
            group_forward[in_og].update(group_forward[grp_o])
            continue

        if in_og and l.strip().startswith('network-object host '):
            ip_val = l.strip().split()[-1]
            if ip_val in name_dict:
                ip_val = name_dict[ip_val]
            if ':' in ip_val:
                pass
            else:
                ip_data = IPv4Network(ip_val+'/32')
            group_forward[in_og].update(set([ip_data]))

            continue

        if in_og and l.strip().startswith('network-object '):
            ip_val = l.split()[-2]

            if ip_val in name_dict:
                ip_val = name_dict[ip_val]
            if ':' in l.split()[-1]:
                pass
            else:
                try:
                    ip_data = IPv4Network(ip_val+'/'+l.split()[-1])
                except NetmaskValueError:
                    if ignore_non_contig:
                        continue
                    else:
                        raise RuntimeError('Invalid Netmask in Object Group %s: %s' % (in_og, l))
            group_forward[in_og].update(set([ip_data]))

            continue






    return singleton_forward, group_forward

def find_matches(in_dict, search_ip):
    """ This function does a group matching based on input of
    a group_dict and an ipaddress.IPv4Address object.

    This will return the list() of matched Object Group names. """
    matches = []
    for g in in_dict:

        if isinstance(in_dict[g], (set, list)):


            for i in in_dict[g]:
                if isinstance(i, IPv4Network):
                    if search_ip in i:
                        matches.append(g)
                        break
        elif isinstance(in_dict[g], IPv4Network):


            if search_ip in in_dict[g]:
                matches.append(g)


    return matches


if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option('-f', '--file',
                      help="The running-configuration from the ASA to analyze",
                      dest='file',
                      default=None)
    parser.add_option('-n', '--non-contiguous',
                      help="Ignores non-contiguous subnet masks in the config. Would raise error otherwise.",
                      dest='ignore_non_contig',
                      action='store_true')
    parser.add_option('-i', '--ip',
                      help="Just show results for object-groups that match an IP Address",
                      dest='ips',
                      default=[], action='append')
    parser.add_option( '--ipd',
                      help="Just show results for object-groups that match an IP Address",
                      dest='ipd',
                      default=[], action='append')
    parser.add_option('-s', '--summary',
                      help="Just show counts of object-groups matched (hide the names)",
                      dest='summary',
                      action='store_true')

    parser.add_option('-c', '--count_internals',
                      help="DEBUGGING: If optimizing, show the number (before and after optimization) of internal network objects used for each object-group ",
                      dest='verbose',
                      action='store_true')
    parser.add_option('-d', '--display_internals',
                      help="DEBUGGING: Display the internal representation of what the object-groups contain as IPs and Subnets.",
                      dest='expand',
                      action='store_true')
    parser.add_option('-g', '--generate_config',
                      help="Create ASA object-group configuration of possibly optimized object-groups (NOTE: nesting and objects removed)",
                      dest='generate',
                      action='store_true')
    parser.add_option('-x', '--xcheck',
                      help="Cross check all possible traffic combos to check for possible blocked traffic due to OGS limits on ASA/Lina (meaningless if upgraded past CSCvm49283)",
                      dest='crosscheck',
                      action='store_true')
    parser.add_option('-r', '--routing',
                      help="Create and use routing table for diaplying blocked traffic (requires -x)",
                      dest='routing',
                      action='store_true')
    parser.add_option('-m', '--max',
                      help="OGS limit (requires -x)",
                      dest='maxcross',
                      action='store',
                      default=10000)


    options, args = parser.parse_args()
myfile = '/Users/srinara2/Downloads/new_show_run.txt'
with open(options.file) as f:
    raw = f.read()
    try:
        cfg = raw.decode('utf-8').splitlines()
    except AttributeError:
        cfg = raw.splitlines()
    print('Read in %s lines of configuration' % (len(cfg)))

    singleton_dict, group_dict = build_object_groups(cfg, ignore_non_contig=True)

    src_objgroup_fromacl,dst_objectgroup_fromacl = build_object_groups_fromacl(cfg,group_dict,ignore_non_contig=True)


    print(options.ips)
    print(options.ipd)

    for ip in options.ips:
        print(''.ljust(40, '*'))
        print('Processing IP source %s...' % (ip,))
        try:
            ip_data = IPv4Address(ip.decode('utf-8'))

        except AttributeError:
            print(True)
            print(type(ip))
            ip_data = IPv4Address(ip)
            print(type(ip_data))
        matched_object_groups = find_matches(group_dict, ip_data)
        matched_objects = find_matches(singleton_dict, ip_data)
        matched_srcobject_groups = find_matches(src_objgroup_fromacl, ip_data)


        #
        # print('IP %s matched  %s objects, %s object-groups (%s srcobjgroup in ACL and %s dstobjgroup in ACL)' % (ip,
        #                                                                                         len(matched_objects),
        #                                                                   len(matched_object_groups),
        #                                                                   len(matched_srcobject_groups),len(matched_dstobject_groups)))

        if not options.summary:  # Full output
            print('IP %s matched the following %s srcobjects' % (ip, len(matched_objects)))
            print('\n'.join(['   %s' % (x,) for x in matched_objects]))
            print('')
            print('IP %s matched the following %s src-object-groups' % (ip, len(matched_srcobject_groups)))

            shown_ogs = []
            for og in matched_srcobject_groups:
                if og in shown_ogs:
                    continue
                # og_was_dupe = False
                # for dupe_og_list in duplicate_object_groups:
                #     if og in dupe_og_list:
                #         print(log_color.red('>> ') + ' , '.join(dupe_og_list) + log_color.red(
                #             ' << These are duplicates'))
                #         if options.expand:
                #             print('        %s' % (', '.join(x.compressed for x in group_dict[og]),))
                #         og_was_dupe = True
                #         shown_ogs.extend(dupe_og_list)
                # if not og_was_dupe:
                print('   ' + og)
                if options.expand:
                    print('        %s' % (', '.join(x.compressed for x in group_dict[og]),))
                shown_ogs.append(og)


    for ip in options.ipd:
        print(''.ljust(40, '*'))
        print('Processing IP dest %s...' % (ip,))
        try:
            ip_data = IPv4Address(ip.decode('utf-8'))
        except AttributeError:
            ip_data = IPv4Address(ip)
        matched_dstobject_groups = find_matches(dst_objectgroup_fromacl, ip_data)
        matched_objects = find_matches(singleton_dict, ip_data)

        if not options.summary:  # Full output# print('IP %s matched the following %s dstobject' % (ip, len(matched_dstobject_groups)))
            print('IP %s matched the following %s objects' % (ip, len(matched_objects)))
            print('\n'.join(['   %s' % (x,) for x in matched_objects]))
            print('')
            print('IP %s matched the following %s dst-object-groups' % (ip, len(matched_dstobject_groups)))

            shown_ogsdst = []
            for og in matched_dstobject_groups:
                if og in  shown_ogsdst:
                    continue
                print('  ' + og)
                if options.expand:
                    print('        %s' % (', '.join(x.compressed for x in group_dict[og]),))
                shown_ogsdst.append(og)


        #
        # if len(options.ips) == 0 and not options.generate:
        #     print('Showing all duplicate Object Groups since NO IP ADDRESS provided')
        #     for dupe_og_list in duplicate_object_groups:
        #         print(log_color.red('>> ') + ' , '.join(dupe_og_list) + log_color.red(' << These are duplicates'))
        #         if options.expand:
        #             print('        %s' % (', '.join(x.compressed for x in group_dict[dupe_og_list[0]]),))

