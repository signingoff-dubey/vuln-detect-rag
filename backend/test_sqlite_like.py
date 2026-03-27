from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class Item(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True)
    name = Column(String)

engine = create_engine('sqlite:///:memory:', echo=False)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

session.add_all([
    Item(name='100% juice'),
    Item(name='100 apples'),
])
session.commit()

escaped_q = '% juice'.replace('%', '\\%')
print("Without escape parameter:")
for item in session.query(Item).filter(Item.name.ilike(f"%{escaped_q}%")).all():
    print(" -", item.name)

print("With escape parameter:")
for item in session.query(Item).filter(Item.name.ilike(f"%{escaped_q}%", escape="\\")).all():
    print(" -", item.name)
