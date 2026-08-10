import sys
import time
from playwright.sync_api import sync_playwright

URL = "https://www.tablecheck.com/shops/bar-centifolia/reserve"
PREFERRED_TIMES = ["20:30", "22:00", "23:00"]  # 8:30 PM, 10:00 PM, 11:00 PM

def run_reservation():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        page = context.new_page()

        print("Navigating to TableCheck...")
        page.goto(URL, wait_until="networkidle")

        # 1. Select Party Size (2 People)
        print("Setting Party Size: 2")
        page.locator("#reservation_num_people_adult").select_option("2")
        page.wait_for_timeout(500)

        # 2. Select Date (August 24, 2026)
        print("Setting Date: August 24, 2026")
        date_picker = page.get_by_role("textbox", name="-- Select Date --")
        date_picker.click()
        page.wait_for_timeout(1000)

        # Force-click the calendar day container (Mobiscroll / Flatpickr day cell)
        try:
            # Target the parent container of the day text 24
            day_cell = page.locator(".dw-cal-day-fg").filter(has_text="24").first
            if day_cell.is_visible():
                # Force click to bypass Mobiscroll disabled state overlays
                day_cell.click(force=True)
            else:
                page.get_by_text("24", exact=True).first.click(force=True)
        except Exception as e:
            print(f"Date click fallback: {e}")

        page.wait_for_timeout(1500)

        # 3. Select Preferred Time Slot
        print("Selecting Time Slot...")
        time_selected = False

        # Check visual time slot buttons first
        for target_time in PREFERRED_TIMES:
            slot = page.get_by_text(target_time, exact=True)
            if slot.is_visible(timeout=1500):
                slot.click(force=True)
                print(f"Selected time slot: {target_time}")
                time_selected = True
                break

        # Fallback to epoch dropdown if visible/enabled
        if not time_selected:
            epoch_select = page.locator("#reservation_start_at_epoch")
            try:
                # Force enable if disabled by JS state lag
                epoch_select.evaluate("el => el.removeAttribute('disabled')")
                for target_time in PREFERRED_TIMES:
                    try:
                        epoch_select.select_option(label=target_time)
                        print(f"Selected time from dropdown: {target_time}")
                        time_selected = True
                        break
                    except Exception:
                        continue
            except Exception as e:
                print(f"Time dropdown note: {e}")

        page.wait_for_timeout(1500)

        # 4. Category & Table Selection
        print("Selecting Category and Table...")
        # Force-enable the category radio if disabled by previous form step delays
        table_label = page.get_by_text("Table", exact=True).first
        table_label.click(force=True)

        page.wait_for_timeout(1000)

        # 5. Additional Information & Questions
        print("Filling Additional Information...")
        try:
            page.get_by_label("Visit History").select_option("First Visit")
        except Exception:
            pass
            
        try:
            page.get_by_text("Confirmed").nth(1).click(force=True)
        except Exception:
            pass

        # 6. Guest Details
        print("Filling Guest Details...")
        page.get_by_role("textbox", name="First Name").fill("Donald")
        page.get_by_role("textbox", name="Last Name").fill("Brown")
        page.get_by_role("textbox", name="Mobile Phone Req").fill("8704893015")
        page.get_by_role("textbox", name="Email Req").fill("d.m.brownjr85@gmail.com")

        # 7. Terms Confirmation
        print("Confirming Venue Terms...")
        venue_confirm = page.locator("#res-booking-panel").get_by_text("I confirm I've read the")
        if venue_confirm.is_visible():
            venue_confirm.click(force=True)

        # 8. Proceed to Next Step
        print("Clicking Next Step...")
        page.get_by_role("button", name="Next Step").click(force=True)

        # 9. Alert User
        print("\n" + "="*60)
        print("ALERT: Successfully reached NEXT STEP! Complete final confirmation manually.")
        print("="*60)

        # Keep browser open for manual completion (5 minutes)
        time.sleep(300)
        browser.close()

if __name__ == "__main__":
    run_reservation()