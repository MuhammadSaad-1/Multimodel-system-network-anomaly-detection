from Real_Time_Extraction_ISP_Lin import run_live_classification as run_live_classification_isp
from Real_Time_Extraction_End_user_Lin import run_live_classification as run_live_classification_end
from Real_Time_Extraction_3Types_Lin import run_live_classification as run_live_classification_router
from collections import deque, Counter
import concurrent.futures
import datetime

def result_from_queue(queue: deque):
    filtered = [name for name, _ in queue if name != "normal"]
    counts = Counter(filtered)
    if not counts:
        return next((item for item in reversed(queue) if item[0] == "normal"), ("normal", 75))
    max_count = max(counts.values())
    if max_count <= 2:
        return next((item for item in reversed(queue) if item[0] == "normal"), ("normal", 75))
    top_candidates = {name for name, cnt in counts.items() if cnt == max_count}
    if len(top_candidates) == 1:
        winner = next(iter(top_candidates))
        return next((item for item in reversed(queue) if item[0] == winner), (winner, 75))
    running_counts = Counter()
    for name, _ in reversed(queue):
        if name in top_candidates:
            running_counts[name] += 1
            if running_counts[name] == max_count:
                return next((item for item in reversed(queue) if item[0] == name), (name, 75))
    return next((item for item in reversed(queue) if item[0] == "normal"), ("normal", 75))

def top3_from_queue(queue: deque):
    counts = Counter(name for name, _ in queue)
    
    sorted_items = sorted(
        counts.items(),
        key=lambda x: (x[1], max(i for i, (name, _) in enumerate(queue) if name == x[0])),
        reverse=True
    )
    
    top_types = [name for name, _ in sorted_items[:3]]
    
    result = []
    for t in top_types:
        score = next(score for name, score in reversed(queue) if name == t)
        result.append((t, score))
    
    return result

def best_choice(end_user_queue, isp_queue, router_queue):
    end_user = result_from_queue(end_user_queue)
    isp = result_from_queue(isp_queue)
    router = result_from_queue(router_queue)
    
    weighted_issues = [
        ("End User", end_user[0], end_user[1], end_user[1] * 1.1),
        ("ISP", isp[0], isp[1], isp[1] * 1.0),
        ("Router", router[0], router[1], router[1] * 0.9)
    ]
    
    filtered_issues = [issue for issue in weighted_issues if issue[1] != "normal"]

    if len(filtered_issues) == 0:
        return [("All", weighted_issues[0][1])]
    
    weighted_issues = filtered_issues
    
    weighted_issues.sort(key=lambda x: x[3], reverse=True)
    
    top_weighted_score = weighted_issues[0][3]
    result = [(weighted_issues[0][0], weighted_issues[0][1], weighted_issues[0][2])]
    
    for i in range(1, len(weighted_issues)):
        if weighted_issues[i][3] >= 0.9 * top_weighted_score:
            result.append((weighted_issues[i][0], weighted_issues[i][1], weighted_issues[i][2]))
        else:
            break
    
    return result
 
def allys_trinket(end_user_queue, isp_queue, router_queue):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future1 = executor.submit(run_live_classification_end)
        future2 = executor.submit(run_live_classification_isp)
        future3 = executor.submit(run_live_classification_router)

        result1 = future1.result()
        result2 = future2.result()
        result3 = future3.result()
        
        end_user_queue.append(result1[0])
        isp_queue.append(result2[0])
        router_queue.append(result3[0])

    return result1, result2, result3

def main():
    results_saved = 10
    end_user_queue = deque(maxlen=results_saved)
    isp_queue = deque(maxlen=results_saved)
    router_queue = deque(maxlen=results_saved)
    
    allys_trinket(end_user_queue, isp_queue, router_queue)

    while True:
        result = allys_trinket(end_user_queue, isp_queue, router_queue)

        def format_section(title, data):
            print(f"{title:<8}: ", end="")
            for i, (name, score) in enumerate(data, start=1):
                print(f"{i}) {name:<15} {score:5.1f}%", end="   ")
            print()
        print(datetime.datetime.now().strftime('%H:%M:%S'))
        print("Latest from each Model")
        format_section("End User", result[0])
        format_section("ISP", result[1])
        format_section("Router", result[2])
        
        print("Top 3 per queue:")
        format_section("End User", top3_from_queue(end_user_queue))
        format_section("ISP", top3_from_queue(isp_queue))
        format_section("Router", top3_from_queue(router_queue))

        choices = best_choice(end_user_queue, isp_queue, router_queue)
        print("Best prediction:")
        if choices:
            if choices[0][0] == "All":
                print("  All Normal")
            else:
                for i, (type_, name, score) in enumerate(choices, start=1):
                    print(f"  {i}) {type_:<8}: {name:<15} {score:5.1f}%")
        print()

if __name__ == "__main__":
    main()