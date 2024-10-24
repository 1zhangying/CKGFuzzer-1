from bs4 import BeautifulSoup
from collections import defaultdict
import os
import shutil
import tempfile
import re
from loguru import logger

from numpy import cov

class BranchState:
    def __init__(self, branch, bucket):
        self.branch = branch
        self.bucket = bucket

    @staticmethod
    def calculate_bucket_count(count):
        if count == 0:
            return 0
        bucket = count.bit_length() - 1
        return 1 << min(bucket, 31)


def html2txt(file_dir, coverage_dir):
    logger.info(file_dir)
    if not os.path.exists(file_dir):
        logger.info(f"The coverage report {file_dir} directory does not exist.")
        return

    # Ensure coverage_dir exists
    os.makedirs(coverage_dir, exist_ok=True)

    files_processed = 0
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            if file.endswith(('.c.html', '.cc.html', '.cpp.html')) and 'fuzz_driver' not in file:
                files_processed += 1
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                soup = BeautifulSoup(html_content, 'html.parser')
                output_text = ""
                for table in soup.find_all('table'):
                    for row in table.find_all('tr'):
                        for cell in row.find_all(['td', 'th']):
                            output_text += cell.get_text(strip=True) + "\t"
                        output_text += "\n"
                    output_text += "\n\n"

                filename = file.split('.')[0]
                txt_file_path = os.path.join(coverage_dir, filename + '.txt')
                with open(txt_file_path, 'w', encoding='utf-8') as f:
                    f.write(output_text)

                logger.info(f"Created: {txt_file_path}")

    if files_processed == 0:
        logger.info(f"No HTML files found in {file_dir}. Created empty coverage directory.")
            


def update_coverage_report(merge_dir, new_report_dir):
    
    if not os.path.exists(new_report_dir):
        logger.info(f"The new report directory {new_report_dir} does not exist.")
        return False, 0, 0, 0, 0, 0, 0, {}

    # Check if new_report_dir is empty
    if not os.listdir(new_report_dir):
        logger.info(f"The new report directory {new_report_dir} is empty.")
        return False, 0, 0, 0, 0, 0, 0, {}

    # Create merge_dir if it doesn't exist
    if not os.path.exists(merge_dir):
        os.makedirs(merge_dir)
        logger.info(f"Created merge directory: {merge_dir}")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Copy the current merge report to the temporary directory
        shutil.copytree(merge_dir, temp_dir, dirs_exist_ok=True)
        
        # Update the temporary directory with the new report
        for filename in os.listdir(new_report_dir):
            if filename.endswith('.txt'):
                temp_file = os.path.join(temp_dir, filename)
                new_file = os.path.join(new_report_dir, filename)
                
                if os.path.exists(temp_file):
                    update_file(temp_file, new_file)
                else:
                    shutil.copy2(new_file, temp_file)

        # Calculate coverages for the original merge directory and the temporary directory
        old_line_cov, old_total_lines, old_covered_lines = calculate_line_coverage(merge_dir)
        new_line_cov, new_total_lines, new_covered_lines = calculate_line_coverage(temp_dir)
        
        
        old_branch_cov, old_total_branches, old_covered_branches = calculate_branch_coverage(merge_dir)
        new_branch_cov, new_total_branches, new_covered_branches = calculate_branch_coverage(temp_dir)
        
        file_coverages = calculate_files_branch_coverages(temp_dir)

        new_branches_covered = new_covered_branches > old_covered_branches
        
        if new_branches_covered:
            shutil.rmtree(merge_dir)
            shutil.copytree(temp_dir, merge_dir)
            logger.info(f"New branches covered. Current covered branches: {new_covered_branches}, Previous covered branches: {old_covered_branches}. Merge report updated.")
            return True, new_line_cov, new_total_lines, new_covered_lines, new_branch_cov, new_total_branches, new_covered_branches, file_coverages
        else:
            logger.info(f"No new branches covered. Current covered branches: {new_covered_branches}, Previous covered branches: {old_covered_branches}. Merge report not updated.")
            return False, old_line_cov, old_total_lines, old_covered_lines, old_branch_cov, old_total_branches, old_covered_branches, file_coverages





def update_file(merge_file, new_file):
    with open(merge_file, 'r') as f:
        merge_lines = f.readlines()
    
    with open(new_file, 'r') as f:
        new_lines = f.readlines()
    
    updated_lines = []
    for merge_line, new_line in zip(merge_lines, new_lines):
        merge_count = extract_count(merge_line)
        new_count = extract_count(new_line)
        
        if merge_count is None and new_count is None:
            updated_lines.append(merge_line)
        elif merge_count is None:
            updated_lines.append(new_line)
        elif new_count is None:
            updated_lines.append(merge_line)
        else:
            max_count = max(merge_count, new_count)
            updated_line = re.sub(r'^\d+\|(\d+)\t', f'{max_count}\t', new_line)
            updated_lines.append(updated_line)
    
    with open(merge_file, 'w') as f:
        f.writelines(updated_lines)

def extract_count(line):
    parts = line.split('\t')
    if len(parts) >= 2:
        count_str = parts[1].strip()
        try:
            count = float(count_str.replace('k', '000'))
            return count if count > 0 else None
        except ValueError:
            return None
    return None


def calculate_line_coverage(merge_dir):
    total_lines = 0
    covered_lines = 0
    
    for filename in os.listdir(merge_dir):
        if filename.endswith('.txt'):
            file_path = os.path.join(merge_dir, filename)
            with open(file_path, 'r') as f:
                for line in f:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        count_str = parts[1].strip()
                        if count_str and not count_str.startswith('Source'):
                            total_lines += 1
                            if count_str != '0':
                                covered_lines += 1

    # print(f"total_lines: {total_lines}")
    # print(f"covered_lines: {covered_lines}")

    if total_lines > 0:
        coverage = covered_lines / total_lines
        return coverage,total_lines,covered_lines
    else:
        return 0,0,0




def calculate_branch_coverage(merge_dir):
    total_branches = 0
    covered_branches = 0

    def parse_count(count_str):
        if count_str.endswith('k') or count_str.endswith('K'):
            return int(float(count_str[:-1]) * 1000)
        elif count_str.endswith('m') or count_str.endswith('M'):
            return int(float(count_str[:-1]) * 1000000)
        return int(float(count_str))  # Use float() to handle decimal points
    
    for filename in os.listdir(merge_dir):
        if filename.endswith('.txt'):
            file_path = os.path.join(merge_dir, filename)
            
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        count_str = parts[1].strip()
                        code = parts[2].strip()
                        branches = identify_branches(code, line_num)
                        for branch in branches:
                            total_branches += 1
                            if count_str and count_str != '0':
                                covered_branches += 1

    if total_branches > 0:
        coverage = covered_branches / total_branches
        return coverage, total_branches, covered_branches
    else:
        return 0, 0, 0
    

def calculate_single_branch_coverage(file_path):
    total_branches = 0
    covered_branches = 0


    def parse_count(count_str):
        if count_str.lower() == 'count':
            return 0  # Skip header row
        if count_str.endswith(('k', 'K')):
            return int(float(count_str[:-1]) * 1000)
        elif count_str.endswith(('m', 'M')):
            return int(float(count_str[:-1]) * 1000000)
        try:
            return int(float(count_str))
        except ValueError:
            return 0  # Return 0 for any non-numeric strings

    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            parts = line.split('\t')
            if len(parts) >= 3:
                count_str = parts[1].strip()
                code = parts[2].strip()
                
                branches = identify_branches(code, line_num)
                for branch in branches:
                    total_branches += 1
                    if count_str and count_str != '0':
                        covered_branches += 1

    if total_branches > 0:
        coverage = covered_branches / total_branches
        return coverage, total_branches, covered_branches
    else:
        return 0, 0, 0
    

def calculate_files_branch_coverages(directory):
    file_coverages = {}
    if not os.path.exists(directory):
        logger.warning(f"Merge directory does not exist: {directory}")
        return file_coverages

    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                coverage, total_branches, covered_branches = calculate_single_branch_coverage(file_path)
                file_coverages[filename] = {
                    'coverage': coverage,
                    'total_branches': total_branches,
                    'covered_branches': covered_branches
                }
            except Exception as e:
                logger.error(f"Error processing file {filename}: {str(e)}")

    return file_coverages


def sort_and_filter_coverages(file_coverages, threshold):
    sorted_coverages = sorted(file_coverages.items(), key=lambda x: x[1]['coverage'])
    low_coverage_files = [filename for filename, data in sorted_coverages if data['coverage'] < threshold]
    return sorted_coverages, low_coverage_files


def identify_branches(code, line_num):
    branches = []
    branch_patterns = [
        (r'\bif\s*\(', 'if'),
        (r'\belse\s+if\s*\(', 'else if'),
        (r'\belse\b', 'else'),
        (r'\bswitch\s*\(', 'switch'),
        (r'\bcase\b', 'case'),
        (r'\bdefault\s*:', 'default'),
        (r'\bfor\s*\(', 'for'),
        (r'\bwhile\s*\(', 'while'),
        (r'\bdo\b', 'do'),

        (r'\?.*:.*', 'ternary'),

        (r'\|\|', 'logical or'),
        (r'&&', 'logical and'),
        
        (r'\bgoto\b', 'goto'),
        (r'\blabel:.*', 'label'),
        (r'\btemplate\s*<', 'template'),
        (r'\bvirtual\b', 'virtual function'),
        (r'\breturn\b', 'return'),
        (r'\btry\b', 'try'),
        (r'\bcatch\s*\(', 'catch'),
        (r'\bthrow\b', 'throw'),
    ]
    
    for pattern, branch_type in branch_patterns:
        if re.search(pattern, code):
            branches.append((line_num, branch_type))
    
    return branches
    
