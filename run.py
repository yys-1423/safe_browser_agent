import os
import csv
import json
import time

from agent import test_agent


def main(result_path, mode):
    csv_path = 'data/response.csv'
    temp_path   = 'temp.json'

    # load existing results (or start empty)
    if os.path.exists(result_path):
        with open(result_path, 'r', encoding='utf-8') as rf:
            results = json.load(rf)
    else:
        results = []

    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            print("sleeping...")
            time.sleep(20)
            print("i'm back!")
            #if idx < 570:
            #    continue
            rec_id      = row['rec_id']
            url         = row['url']
            html_path   = row['found_path']
            instruction = row['response']

            print("=" * 80)
            print("\n\n....STARTING....\n\n")
            print(f"[{idx}] rec_id: {rec_id}")
            print(f"URL: {url}")
            print(f"HTML Path: {html_path}")
            print(f"Instruction: {instruction}\n\n")
            print("-" * 80)
            print("\n\n\n\n\n")

            # run the agent, get back the canonical file_url & task_text you built
            result, file_url, task_text = test_agent(url, html_path, instruction, mode)

            # read whatever actions were dumped into temp.json
            if os.path.exists(temp_path):
                with open(temp_path, 'r', encoding='utf-8') as tf:
                    content = json.load(tf)
            else:
                content = None  # or [] if you prefer

            # build our entry and append it
            entry = {
                'result' : result,
                'rec_id':   rec_id,
                'url':      url,
                'file_url': file_url,
                'task_text': task_text,
                'action_history':  content
            }
            results.append(entry)

            # write back the full array
            with open(result_path, 'w', encoding='utf-8') as rf:
                json.dump(results, rf, ensure_ascii=False, indent=2)

    return results

main("result/result_5n_3.json",3)
main("result/result_5n_4.json",4)
main("result/result_5n_1.json",1)
