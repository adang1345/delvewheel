import datetime
import threading
import urllib.request
import urllib.error
import json
import re
import io
import zipfile

# datetime that delvewheel 0.0.1 was first released
START_DATETIME = datetime.datetime.fromisoformat('2020-12-23T19:22:47.573658Z')
THREADS = 100
RETRIES = 10
PRINT_LOCK = threading.Lock()


def print_safe(*args, **kwargs):
    with PRINT_LOCK:
        print(*args, **kwargs)


def find_delvewheel_packages(packages: list[str]):
    for package in packages:
        package_exists = True
        for i in range(RETRIES):
            try:
                json_data = json.load(urllib.request.urlopen(f'https://pypi.org/pypi/{package}/json'))
                break
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    package_exists = False
                    break
            except:
                pass
            else:
                break
        else:
            print_safe(f'Failed to load https://pypi.org/pypi/{package}/json after {RETRIES} tries')
            continue
        if not package_exists:
            continue
        version = json_data['info']['version']
        # print_safe(package, version)
        for release_file in json_data['releases'][version]:
            if datetime.datetime.fromisoformat(release_file['upload_time_iso_8601']) <= START_DATETIME:
                # print_safe(f'{package} is too old')
                break
            release_filename = release_file['filename']
            if any(release_filename.endswith(x) for x in ('win_amd64.whl', 'win32.whl', 'win_arm64.whl')):
                try:
                    with io.BytesIO(urllib.request.urlopen(release_file['url']).read()) as zip_file:
                        zip_path = zipfile.Path(zip_file, f'{release_filename[:release_filename.index('-')]}-{version}.dist-info/DELVEWHEEL')
                except:
                    print_safe(f'Error opening zip file {release_filename}')
                    break
                if zip_path.exists():
                    delvewheel_packages.add(package)
                    print_safe(package, version)
                    break


# get list of all PyPI packages
print('Getting list of all PyPI packages ... ', end='', flush=True)
html = urllib.request.urlopen('https://pypi.org/simple/').read().decode('utf-8')
pattern = re.compile(r'>([^<]+)</a>')
all_packages = [match[1] for match in re.finditer(pattern, html)]
# all_packages = ('numpy',)
print('Done')

delvewheel_packages = set()
threads = []
chunk_size = max(1, len(all_packages) // THREADS)
for i in range(0, len(all_packages), chunk_size):
    thread = threading.Thread(target=find_delvewheel_packages, args=(all_packages[i: i + chunk_size],))
    threads.append(thread)
    thread.start()
print(f'Threads: {len(threads)}')
for thread in threads:
    thread.join()
print(len(delvewheel_packages))
print(delvewheel_packages)
