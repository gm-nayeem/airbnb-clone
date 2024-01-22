"use client";

import { usePathname, useSearchParams } from "next/navigation";

import CategoryBox from "../CategoryBox";
import Container from "../Container";
import { categoriesData } from "@/utils/data";

const Categories = () => {
  const params = useSearchParams();
  const category = params?.get("category");
  const pathname = usePathname();
  const isMainPage = pathname === "/";

  if (!isMainPage) {
    return null;
  }

  return (
    <Container>
      <div
        className="
          pt-4
          flex
          flex-row
          items-center
          justify-between
          overflow-x-auto
        "
      >
        {categoriesData?.length > 0
          ? categoriesData.map((item) => (
              <CategoryBox
                key={item.label}
                label={item.label}
                icon={item.icon}
                selected={category === item.label}
              />
            ))
          : null}
      </div>
    </Container>
  );
};

export default Categories;
