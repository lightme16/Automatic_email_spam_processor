import itertools
import operator
from virus_total_apis import PublicApi as VirusTotalPublicApi

API_KEY = '1f8ebb0661d8fe5554fbbc29634cce0d95ac55cd0e6801d5415d62307d5cd03b'
vt = VirusTotalPublicApi(API_KEY)

def most_common(L):
  # get an iterable of (item, iterable) pairs
  SL = sorted((x, i) for i, x in enumerate(L))
  # print 'SL:', SL
  groups = itertools.groupby(SL, key=operator.itemgetter(0))
  # auxiliary function to get "quality" for an item
  def _auxfun(g):
    item, iterable = g
    count = 0
    min_index = len(L)
    for _, where in iterable:
      count += 1
      min_index = min(min_index, where)
    # print 'item %r, count %r, minind %r' % (item, count, min_index)
    return count, -min_index
  # pick the highest-count/earliest item
  return max(groups, key=_auxfun)[0]

def check_url(site):
    try:
        warring = 0
        issues = []
        scans = vt.get_url_report(site)['results']['scans']

        for key, value in scans.items():
            #print key, value
            if value['detected'] == True:
                warring +=1
            if value['result'] != 'clean site':
                if value['result'] != 'unrated site':
                    issues.append(value['result'])
        return warring < 1,most_common(issues)
    except Exception:
        return True, 'clean site'

def check_file(path):
    pass

