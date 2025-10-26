"""OSINT (Open Source Intelligence) tools"""

import requests
import re
from termcolor import colored
from bs4 import BeautifulSoup
from utils.ascii_art import AsciiArt


class OSINTTools:
    """Open Source Intelligence gathering tools"""

    def __init__(self, target):
        self.target = target

    def email_harvest(self):
        """Harvest email addresses from target website"""
        print(f"\n{colored('Harvesting email addresses...', 'cyan')}")
        print(AsciiArt.tool_category_banner('forensics'))

        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

        try:
            target_url = self.target if self.target.startswith('http') else f'http://{self.target}'
            response = requests.get(target_url, timeout=10)

            emails = set(re.findall(email_pattern, response.text))

            if emails:
                print(f"\n{colored('Email Addresses Found:', 'green', attrs=['bold'])} {len(emails)}\n")
                for email in sorted(emails):
                    print(f"  📧 {colored(email, 'green')}")
                AsciiArt.success_message("Email harvesting completed")
            else:
                AsciiArt.info_message("No email addresses found")

            return list(emails)

        except Exception as e:
            AsciiArt.error_message(f"Email harvesting failed: {str(e)}")
            return []

    def social_links(self):
        """Find social media links"""
        print(f"\n{colored('Finding social media links...', 'cyan')}")

        social_platforms = {
            'Twitter': r'(https?://(?:www\.)?twitter\.com/[a-zA-Z0-9_]+)',
            'Facebook': r'(https?://(?:www\.)?facebook\.com/[a-zA-Z0-9.]+)',
            'LinkedIn': r'(https?://(?:www\.)?linkedin\.com/(?:in|company)/[a-zA-Z0-9-]+)',
            'Instagram': r'(https?://(?:www\.)?instagram\.com/[a-zA-Z0-9_.]+)',
            'GitHub': r'(https?://(?:www\.)?github\.com/[a-zA-Z0-9-]+)',
            'YouTube': r'(https?://(?:www\.)?youtube\.com/(?:c|channel|user)/[a-zA-Z0-9_-]+)'
        }

        try:
            target_url = self.target if self.target.startswith('http') else f'http://{self.target}'
            response = requests.get(target_url, timeout=10)

            found_links = {}

            for platform, pattern in social_platforms.items():
                matches = set(re.findall(pattern, response.text))
                if matches:
                    found_links[platform] = list(matches)

            if found_links:
                print(f"\n{colored('Social Media Links Found:', 'green', attrs=['bold'])}\n")
                for platform, links in found_links.items():
                    print(f"{colored(platform, 'cyan')}:")
                    for link in links:
                        print(f"  🔗 {link}")
                    print()
                AsciiArt.success_message("Social media discovery completed")
            else:
                AsciiArt.info_message("No social media links found")

            return found_links

        except Exception as e:
            AsciiArt.error_message(f"Social media scan failed: {str(e)}")
            return {}

    def metadata_extract(self, url):
        """Extract metadata from web page"""
        print(f"\n{colored('Extracting metadata...', 'cyan')}")

        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            metadata = {
                'title': soup.find('title').text if soup.find('title') else 'Not found',
                'description': '',
                'keywords': '',
                'author': '',
                'generator': '',
                'og_title': '',
                'og_description': '',
                'twitter_card': ''
            }

            # Meta tags
            for tag in soup.find_all('meta'):
                if tag.get('name') == 'description':
                    metadata['description'] = tag.get('content', '')
                elif tag.get('name') == 'keywords':
                    metadata['keywords'] = tag.get('content', '')
                elif tag.get('name') == 'author':
                    metadata['author'] = tag.get('content', '')
                elif tag.get('name') == 'generator':
                    metadata['generator'] = tag.get('content', '')
                elif tag.get('property') == 'og:title':
                    metadata['og_title'] = tag.get('content', '')
                elif tag.get('property') == 'og:description':
                    metadata['og_description'] = tag.get('content', '')
                elif tag.get('name') == 'twitter:card':
                    metadata['twitter_card'] = tag.get('content', '')

            print(f"\n{colored('Metadata:', 'yellow', attrs=['bold'])}")
            for key, value in metadata.items():
                if value:
                    print(f"  {colored(key.title(), 'cyan')}: {value[:100]}")

            AsciiArt.success_message("Metadata extraction completed")
            return metadata

        except Exception as e:
            AsciiArt.error_message(f"Metadata extraction failed: {str(e)}")
            return {}

    def tech_stack_detect(self):
        """Detect technology stack"""
        print(f"\n{colored('Detecting technology stack...', 'cyan')}")

        try:
            target_url = self.target if self.target.startswith('http') else f'http://{self.target}'
            response = requests.get(target_url, timeout=10)

            tech_stack = []

            # Server
            if 'Server' in response.headers:
                tech_stack.append(('Server', response.headers['Server']))

            # Powered by
            if 'X-Powered-By' in response.headers:
                tech_stack.append(('Powered-By', response.headers['X-Powered-By']))

            # Check HTML for frameworks
            html = response.text.lower()
            frameworks = {
                'React': ['react', '_react'],
                'Vue.js': ['vue', '__vue__'],
                'Angular': ['ng-', 'angular'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap'],
                'Tailwind': ['tailwind'],
                'WordPress': ['wp-content', 'wp-includes'],
                'Django': ['csrfmiddlewaretoken', '__admin_media_prefix__'],
                'Flask': ['werkzeug'],
                'Laravel': ['laravel'],
                'Express': ['x-powered-by: express'],
                'Next.js': ['__next'],
                'Gatsby': ['gatsby']
            }

            for tech, signatures in frameworks.items():
                if any(sig in html for sig in signatures):
                    tech_stack.append(('Framework', tech))

            if tech_stack:
                print(f"\n{colored('Technology Stack:', 'green', attrs=['bold'])}\n")
                for category, tech in tech_stack:
                    print(f"  {colored(category, 'cyan')}: {colored(tech, 'green')}")
                AsciiArt.success_message("Technology detection completed")
            else:
                AsciiArt.info_message("No specific technologies identified")

            return tech_stack

        except Exception as e:
            AsciiArt.error_message(f"Technology detection failed: {str(e)}")
            return []
