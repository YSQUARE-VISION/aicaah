"""지적의 경량 순위와 요청 시 SQL 근거 조회. 판정 패스에서 연관 그래프를 순회하지 않는다."""
import hashlib
import re
import time
from collections import Counter
from pathlib import PurePosixPath
from judging import check
from storage import ledger, metadata_store


def build(findings, authority="document"):
    """이미 판정한 지적만 종류별 정렬한다. 소스·그래프·DB를 읽지 않는다."""
    started = time.perf_counter()
    unique = {}; occurrences = Counter(); locations = {}
    for finding in findings:
        key = check.finding_key(finding)
        unique.setdefault(key, finding); occurrences[key] += 1
        locations.setdefault(key,Counter())[(finding.file,finding.line)] += 1
    actions = {'L3': ('delete-unused', '미사용 선언과 불필요한 쓰기 삭제'),
               'L4': ('move-owner', '실제 소비 계층으로 선언·컴파일 입력 이동'),
               'L2': ('direct-public-access', '공개 접근과 직접 호출로 변경')}
    reflection = {'W1','W2','W3','W4','W5','W6','W7','W9','W10'}
    rows = []
    for key, finding in unique.items():
        code = finding.code
        kind, action = actions.get(code, ('contract-review', '계약과 현행 구현 대조'))
        band = 1 if code in actions else 2
        if code.startswith(('D','P')):
            kind, action, band = 'blocking-error', '대조 차단 오류 필수 수정: 문서 반영으로 대체 불가', -1
        elif code == 'W12':
            kind, action, band = 'verify-behavior', '테스트 작성·등록 → 실제 실행 → 실패 수정·재실행 → 현재 증거 수집 → 하네스 재판정', 0
        elif authority == 'code' and code in reflection:
            kind, action, band = 'document-reflection', '현재 코드를 소유 문서에 반영', 0
        rows.append({'id': hashlib.sha256(key.encode()).hexdigest()[:16], 'findingId': key,
                     'code': code, 'file': finding.file, 'line': finding.line, 'message': finding.message, 'rule': finding.rule,
                     'actionKind': kind, 'action': action, 'priorityBand': band,
                     'evidenceStatus': 'on-request', 'linkedUniqueCount': None,
                     'occurrenceCount': occurrences[key], 'authority': authority,
                     'locations':[{'file':f,'line':line,'occurrences':count} for (f,line),count in sorted(locations[key].items())],
                     'mustFix': kind in ('blocking-error', 'verify-behavior'),
                     'modeIndependent': kind in ('blocking-error', 'verify-behavior'),
                     'blocksResolution': kind in ('blocking-error', 'verify-behavior'),
                     'requiredAction': ('repair-source-reference' if code.startswith('P') else
                                        'repair-document-contract' if code.startswith('D') else kind),
                     'repairInstruction': ('원본 선언·참조와 실제 컴파일 입력을 확인해 오류를 수정한다. 코드→문서 모드에서도 필수이며 문서 상태 변경·제외로 해소하지 않는다.'
                                           if code.startswith('P') else
                                           '문서 파싱·계약 오류를 수정해 대조를 복구한다. 코드→문서 모드에서도 필수이며 운영 코드를 오래된 문서에 맞춰 바꾸지 않는다.'
                                           if code.startswith('D') else
                                           '동작 조건·보장을 검증하는 테스트 코드를 작성·보완하고 감시·소유·멤버·검사 계층·실행 입구와 동작 행에 등록한다. '
                                           '운영 코드 수정 전에 테스트를 먼저 작성하고 기준 실행의 실패를 남긴다. 앱 수준은 기존 메인 앱 API로 요청·응답하는 단위 테스트를 실제 실행한다. computer use나 별도 복사 앱으로 대체하지 않는다. '
                                           '실패한 검사·구현을 수정해 같은 테스트를 재실행한다. 현재 계약·검사·입력에 대응하는 원 요청·응답, 프로세스·로드 DLL 지문, 개별 기대값·실제값과 결과를 수집한 뒤 하네스를 재판정한다. '
                                           '편집 정책을 준수하며, 상태·검사 수준을 낮추거나 통과 증거를 임의 작성하지 않는다. W12가 남으면 완료로 보고하지 않는다.'
                                           if code == 'W12' else action)})
    rows.sort(key=lambda row: (row['priorityBand'], not row['mustFix'], row['file'], row['line'], row['findingId']))
    for rank, row in enumerate(rows, 1): row['priorityRank'] = rank
    grouped = {}
    for row in rows:
        # Only a recorded contract identity proves a shared cause. Text similarity
        # or nearby locations never merge separate obligations.
        behavior = row['rule'].removeprefix('behavior:') if row['code'] == 'W12' and row['rule'].startswith('behavior:') else ''
        key = ('behavior',row['file'],behavior) if behavior else ('finding',row['id'])
        group = grouped.setdefault(key, {'id':hashlib.sha256(repr(key).encode()).hexdigest()[:16],
            'behaviorId':behavior, 'file':row['file'], 'line':row['line'], 'code':row['code'],
            'actionKind':row['actionKind'], 'priorityRank':row['priorityRank'], 'priorityBand':row['priorityBand'],
            'mustFix':False, 'blocksResolution':False, 'uniqueFindings':0, 'occurrences':0, 'findingIds':[]})
        group['findingIds'].append(row['id']); group['uniqueFindings'] += 1
        group['occurrences'] += row['occurrenceCount']
        group['mustFix'] |= row['mustFix']; group['blocksResolution'] |= row['blocksResolution']
    return {'authority': authority, 'findingPriority': rows,
            'groups':list(grouped.values()), 'groupCount':len(grouped),
            'uniqueFindings': len(rows), 'occurrences': len(findings),
            'elapsedSeconds': time.perf_counter()-started,
            'estimateKind': 'action-category-only-links-not-queried'}


def listing(ranking, limit=20, order='asc', offset=0, finding_id=None, groups=False, group_id=None):
    """저장 지적의 작은 순위 목록. ID 지정은 SQL 상세 조회를 요구하며 후보를 만들지 않는다."""
    if limit < 0 or offset < 0 or order not in ('asc','desc'):
        raise ValueError('invalid limit, offset or order')
    if sum((finding_id is not None, bool(groups), group_id is not None)) > 1:
        raise ValueError('choose one of finding_id, groups or group_id')
    if (groups or group_id is not None) and 'groups' not in ranking:
        ranking = build([check.Finding(r['code'],r['file'],r['line'],r['message'],rule=r.get('rule',''))
                         for r in ranking.get('findingPriority',[]) for _ in range(r.get('occurrenceCount',1))],ranking.get('authority','document'))
    rows = ranking.get('findingPriority', [])
    if groups:
        ordered = ranking['groups'] if order == 'asc' else list(reversed(ranking['groups']))
        selected = ordered[offset:offset+limit] if limit else ordered[offset:]
        return {'authority':ranking.get('authority'), 'total':len(ordered), 'uniqueFindings':ranking['uniqueFindings'],
                'occurrences':ranking['occurrences'], 'groupCount':len(ordered), 'order':order, 'offset':offset,'limit':limit,
                'groups':selected, 'detailRequest':'priority --group <id>',
                'nextOffset':offset+len(selected) if offset+len(selected)<len(ordered) else None,
                'instruction':'P/D 선행 수정. 각 묶음은 priority --group <id>로 모든 지적을 조회하고 개별 근거는 priority --id <id>로 확인한다. W12는 실제 검사·현재 증거·재판정 의무를 유지한다.'}
    if group_id is not None:
        group = next((g for g in ranking['groups'] if g['id']==group_id),None)
        if group is None: raise KeyError(group_id)
        ids = set(group['findingIds']); rows = [r for r in rows if r['id'] in ids]
    if finding_id is not None:
        row = next((r for r in rows if finding_id in (r['id'],r['findingId'])), None)
        if row is None: raise KeyError(finding_id)
        return {'finding':row, 'detailRequest':'/priority?id='+row['id'], 'evidenceStatus':'sql-request-required'}
    ordered = rows if order == 'asc' else reversed(rows)
    if order == 'desc': ordered = list(ordered)
    selected = ordered[offset:offset+limit] if limit else ordered[offset:]
    fields = ('id','code','file','line','message','actionKind','action','priorityRank','priorityBand',
              'evidenceStatus','linkedUniqueCount','occurrenceCount','mustFix','modeIndependent',
              'blocksResolution','requiredAction','repairInstruction','locations')
    return {'authority':ranking.get('authority'), 'total':len(rows), 'order':order,
            'offset':offset, 'limit':limit, 'findings':[{k:r[k] for k in fields if k in r} for r in selected],
            'instruction':'P/D 대조 차단 오류를 모드와 무관하게 먼저 수정한다. W12의 mustFix는 테스트 작성·등록·실행·실패 수정·재실행·현재 증거 수집·하네스 재판정을 끝낼 의무다. 각 지적의 repairInstruction을 따른다. 처리 순위의 지적 ID를 지정해 SQL 연관 근거를 요청한다. SQL 선언이 없어도 file/line/message 근거를 조사하며 상태 변경으로 대체하지 않는다. 미조회 연계 수는 미확정이다.',
            'detailRequest':'/priority?id=<id>', 'estimateKind':'action-category-only-links-not-queried'}


def detail(root, ranking, finding_id, meta, relations, analysis=None, limit=100):
    """요청한 지적의 선언·직접 참조를 기존 관계형 SQL 테이블에서만 조회한다."""
    if not 1 <= limit <= 1000: raise ValueError('detail limit must be 1..1000')
    started = time.perf_counter(); row = listing(ranking, finding_id=finding_id)['finding']
    result = {'finding':row, 'evidenceSource':'folder-owned-sql-tables', 'declarations':[],
              'consumers':[], 'dependencies':[], 'documents':[], 'truncated':False,
              'linkedUniqueCount':None, 'sqlQueries':0, 'queriedFolders':[]}
    if meta is None:
        result.update(evidenceStatus='metadata-unavailable', reason='완료된 메타데이터가 없습니다.')
        return result
    if row['code'] in ('I3','S1') and not PurePosixPath(row['file']).suffix:
        return _folder_detail(root,row,meta,relations,limit,result)
    token_match = re.search(r'(?:method|field|property|class|struct|interface|event|ctor|const) ([\w.]+)', row['findingId'].split('|',3)[-1])
    token = token_match.group(1) if token_match else None
    rel = row['file']; symbol = None
    # Private string calls point to a different file. Resolve only existing bad-edge
    # targets for this caller, never rescan graph edges or files.
    if row['code'] == 'L2' and analysis is not None:
        graph = analysis.graph; targets = set()
        for source, target in analysis.bad_edges:
            caller, decl = graph.decls[source], graph.decls[target]
            if not 0 <= caller.get('file',-1) < len(graph.files) or graph.files[caller['file']] != rel: continue
            owner = decl.get('container',-1)
            name = ((graph.decls[owner]['name']+'.') if owner is not None and owner >= 0 else '') + decl['name']
            if token == name and 0 <= decl.get('file',-1) < len(graph.files): targets.add((graph.files[decl['file']],decl['key']))
        if len(targets) != 1:
            result.update(evidenceStatus='target-ambiguous', reason='비공개 대상이 유일하지 않습니다.')
            return result
        rel, symbol = next(iter(targets))
        if not symbol.startswith('py:'): symbol = symbol.rsplit('@',1)[0]
    anchor = '.spec-conformance/Cache/file-meta/'+rel+'.row'
    raw = metadata_store.declarations(root, rel, limit + 1, symbol=symbol, token=token)
    result['sqlQueries'] += 1
    targets=[]
    for key,sym,owner,payload in raw:
        node = payload
        named = not token or key.split('#',1)[-1] == token or node.get('alias','').split('#',1)[-1] == token
        if symbol or (named and node.get('line') == row['line']): targets.append((key,sym,owner,node))
    if not targets and token and not symbol:
        # Layer diagnostics show the immediate owner (Inner.Member), whereas
        # persisted keys include outer owners (Outer.Inner.Member). Query only
        # this file's indexed rows; no source or global graph traversal.
        raw = metadata_store.declarations(root, rel, limit + 1, token=token, nested=True)
        result['sqlQueries'] += 1
        for key,sym,owner,payload in raw:
            node=payload
            alias=node.get('alias',key).split('#',1)[-1]
            if alias.endswith('.'+token) and node.get('line')==row['line']:
                targets.append((key,sym,owner,node))
    if len(targets) != 1 or len(raw)>limit:
        result.update(evidenceStatus='declaration-unavailable', reason='현재 SQL 선언 위치가 유일하지 않거나 요청 한도를 넘습니다.', truncated=len(raw)>limit)
        return result
    key,sym,owner,node=targets[0]
    result['declarations']=[dict(node,key=key,symbol=sym,owner=owner)]
    result['documents']=sorted(set(meta.places.get(key,())) | set(meta.places.get(owner,())) | set(meta.places.get(rel,())))
    routes = relations.get('refs',{}).get('incoming')
    if routes is None:
        routes = {key: ledger.table_users(root,'.spec-conformance/Cache/file-meta',{key},'target')}
    folders={str(PurePosixPath(f).parent) for f in routes.get(key,())};folders.add(str(PurePosixPath(rel).parent))
    remaining=limit
    for folder in sorted(folders):
        shard='.spec-conformance/Cache/file-meta/'+folder+'/_'
        result['queriedFolders'].append(folder)
        values = metadata_store.edges(root, shard, [key], remaining + 1)
        result['sqlQueries'] += 1
        if len(values)>remaining: result['truncated']=True
        for a,b,file,line,write,guess in values[:remaining]:
            result['consumers'].append({'from':a,'to':b,'file':file,'line':line,'written':bool(write),'guessed':bool(guess)})
        remaining-=min(len(values),remaining)
        if remaining==0: result['truncated']=True;break
    values = metadata_store.edges(root, anchor, [key], limit + 1, incoming=False)
    result['sqlQueries'] += 1
    result['dependencies']=[{'from':a,'to':b,'file':file,'line':line,'written':bool(write),'guessed':bool(guess)} for a,b,file,line,write,guess in values[:limit]]
    result['truncated'] |= len(values)>limit
    result.update(evidenceStatus='sql-direct-relations', elapsedSeconds=time.perf_counter()-started,
                  scope='요청 선언의 직접 읽기·쓰기·의존 관계. 전이 폐쇄나 확정 해소 수가 아님.',
                  instruction='SQL 선언·소비부·소유 문서를 확인해 조치한다. 직렬화·동적 참조·PS1 입력은 해당 소스에서 확인한다. 추가 연결은 관련 지적 ID를 목록에서 선택해 요청한다.')
    return result


def _folder_detail(root, row, meta, relations, limit, result):
    """요청한 폴더 지적의 형·직접 소비를 해당 폴더 DB와 기존 역참조 파일 색인에서만 읽는다."""
    started=time.perf_counter();folder=row['file'].rstrip('/')
    anchor='.spec-conformance/Cache/file-meta/'+folder+'/_'
    result['queriedFolders'].append(folder)
    raw = metadata_store.folder_types(root, folder, limit + 1)
    result['sqlQueries'] += 1
    result['truncated']=len(raw)>limit
    match=re.search(r'클래스\(([^)]+)\)',row['message'])
    names={name.strip() for name in match.group(1).split(',')} if match else None
    keys=[];documents=set()
    for key,symbol,owner,payload in raw[:limit]:
        node=payload
        if names is not None and node.get('name') not in names:continue
        result['declarations'].append(dict(node,key=key,symbol=symbol,owner=owner))
        keys.append(key)
        documents.update(meta.places.get(key,()));documents.update(meta.places.get(node.get('file',''),()))
    result['documents']=sorted(documents)
    if not keys:
        result.update(evidenceStatus='declaration-unavailable',reason='요청 폴더의 보고된 형을 현재 SQL 행에서 찾지 못했습니다.')
        return result
    members = metadata_store.members(root, anchor, keys, limit + 1)
    result['sqlQueries'] += 1
    result['truncated'] |= len(members)>limit
    targets=list(dict.fromkeys(keys+[key for key, in members[:limit]]))
    incoming=relations.get('refs',{}).get('incoming')
    if incoming is None:
        incoming={key:ledger.table_users(root,'.spec-conformance/Cache/file-meta',{key},'target') for key in targets}
    folders={folder}
    for key in targets:folders.update(str(PurePosixPath(file).parent) for file in incoming.get(key,()))
    remaining=limit
    for consumer_folder in sorted(folders):
        shard='.spec-conformance/Cache/file-meta/'+consumer_folder+'/_'
        if consumer_folder not in result['queriedFolders']:result['queriedFolders'].append(consumer_folder)
        edges = metadata_store.edges(root, shard, targets, remaining + 1)
        result['sqlQueries'] += 1
        result['truncated'] |= len(edges)>remaining
        for source,target,file,line,write,guess in edges[:remaining]:
            result['consumers'].append({'from':source,'to':target,'file':file,'line':line,'written':bool(write),'guessed':bool(guess)})
        remaining-=min(len(edges),remaining)
        if remaining==0:
            result['truncated']=True
            break
    result.update(evidenceStatus='sql-folder-direct-relations',elapsedSeconds=time.perf_counter()-started,
        scope='요청 폴더의 보고된 형과 한도 안의 직접 소비. 전이 폐쇄·확정 해소 수가 아님.',
        instruction='보고된 형의 실제 소유권·소비부를 확인한다. truncated이면 더 큰 한도나 구체적 지적 ID로 요청한다. 저장된 SQL 행과 역참조 파일 색인만 사용한다.')
    return result
